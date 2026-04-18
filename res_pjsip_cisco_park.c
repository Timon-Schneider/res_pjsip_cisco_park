/* Copyright (C) 2024 Timon Schneider info@timon-schneider.com
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * res_pjsip_cisco_park.c
 *
 * Intercepts Cisco x-cisco-remotecc ParkMonitor REFER requests (sent when
 * the user presses the Park softkey on a CP-8xxx) and parks the
 * remote party into Asterisk's default res_parking lot, then signals the
 * phone with a refer-NOTIFY carrying an application/dialog-info+xml body
 * that contains the parking slot number — so the phone's display shows
 * "Parked at 71" (or whichever slot res_parking picked).
 *
 * Add to /etc/asterisk/extensions_custom.conf:
 *   [cisco-park]
 *   exten => s,1,NoOp(Cisco Park peer ${CHANNEL})
 *    same => n,Park(default,s,60)
 *    same => n,Hangup()
 *
 *   [cisco-park-phone]
 *   exten => s,1,NoOp(Cisco Park phone leg ${CHANNEL})
 *    same => n,Wait(1)
 *    same => n,Hangup()
 *
 * Why both contexts?  We redirect both bridge members simultaneously:
 *   - peer  -> [cisco-park]        -> Park(default,s,60)
 *   - phone -> [cisco-park-phone]  -> Wait(1) -> Hangup()
 * Redirecting the phone's leg into a short Wait() prevents FreePBX's
 * post-bridge missed-call Gosub from running and, more importantly,
 * keeps the phone's channel alive long enough for our "Parked at <slot>"
 * NOTIFY to land before we emit BYE.
 *
 * If [cisco-park-phone] isn't defined, we fall back to sending the
 * NOTIFY and then soft-hanging-up the phone leg ourselves.
 *
 * On successful park:
 *   Phone -> REFER   (Content-Type: application/x-cisco-remotecc-request+xml)
 *          <- 202 Accepted
 *          <- NOTIFY (Event: refer,  Subscription-State: active;expires=3600
 *                     Content-Type: application/dialog-info+xml
 *                     body: <call:park><event>parked</event>, entity=sip:<slot>@host)
 *          <- NOTIFY (Event: refer,  Subscription-State: terminated;reason=noresource
 *                     <state>terminated</state> in body)
 *          <- BYE    (phone's own leg, after Wait(1) in [cisco-park-phone])
 */

/* Required for externally-compiled Asterisk modules */
#define AST_MODULE_SELF_SYM __local_ast_module_self

/*** MODULEINFO
    <depend>pjproject</depend>
    <depend>res_pjsip</depend>
    <depend>res_pjsip_session</depend>
    <depend>res_parking</depend>
    <support_level>extended</support_level>
 ***/

#include "asterisk.h"
#include "asterisk/module.h"
#include "asterisk/res_pjsip.h"
#include "asterisk/res_pjsip_session.h"
#include "asterisk/channel.h"
#include "asterisk/bridge.h"
#include "asterisk/pbx.h"
#include "asterisk/strings.h"
#include "asterisk/utils.h"
#include "asterisk/logger.h"
#include "asterisk/astobj2.h"
#include "asterisk/lock.h"
#include "asterisk/time.h"
#include "asterisk/stasis.h"
#include "asterisk/stasis_channels.h"
#include "asterisk/parking.h"

#include <pjsip.h>
#include <pjsip_ua.h>
#include <pthread.h>

#define CISCO_PARK_CONTEXT        "cisco-park"
#define CISCO_PARK_EXTEN          "s"
#define CISCO_PARK_PRIO           1

/* Small helper context that the phone leg is redirected into while
 * we're still negotiating the park with res_parking — see header. */
#define CISCO_PARK_PHONE_CONTEXT  "cisco-park-phone"
#define CISCO_PARK_PHONE_EXTEN    "s"
#define CISCO_PARK_PHONE_PRIO     1

#define CISCO_PARK_WAIT_SEC       3

/* ---------- helpers (copied from res_pjsip_cisco_conference) ---------- */

static int xml_get(const char *xml, const char *tag, char *out, size_t sz)
{
    char open[256], close[256];
    const char *p, *q;
    size_t len;

    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);

    p = strstr(xml, open);
    if (!p) return -1;
    p += strlen(open);
    q = strstr(p, close);
    if (!q) return -1;

    len = (size_t)(q - p);
    if (len >= sz) return -1;
    memcpy(out, p, len);
    out[len] = '\0';

    while (len > 0 && (out[len-1] == ' ' || out[len-1] == '\t'
                       || out[len-1] == '\r' || out[len-1] == '\n'))
        out[--len] = '\0';

    return 0;
}

static struct ast_channel *channel_for_dialog(const char *call_id,
    const char *phone_tag, const char *asterisk_tag)
{
    pj_str_t cid  = { (char *)call_id,     (pj_ssize_t)strlen(call_id) };
    pj_str_t ltag = { (char *)asterisk_tag, (pj_ssize_t)strlen(asterisk_tag) };
    pj_str_t rtag = { (char *)phone_tag,    (pj_ssize_t)strlen(phone_tag) };
    pjsip_dialog *dlg;
    struct ast_sip_session *session;
    struct ast_channel *chan = NULL;

    dlg = pjsip_ua_find_dialog(&cid, &ltag, &rtag, PJ_TRUE);
    if (!dlg)
        dlg = pjsip_ua_find_dialog(&cid, &rtag, &ltag, PJ_TRUE);
    if (!dlg) {
        ast_log(LOG_WARNING, "CiscoPark: dialog not found for call-id='%s'\n", call_id);
        return NULL;
    }

    session = ast_sip_dialog_get_session(dlg);
    pjsip_dlg_dec_lock(dlg);

    if (!session) {
        ast_log(LOG_WARNING, "CiscoPark: no session for call-id='%s'\n", call_id);
        return NULL;
    }

    if (session->channel)
        chan = ast_channel_ref(session->channel);
    ao2_ref(session, -1);

    if (!chan)
        ast_log(LOG_WARNING, "CiscoPark: no channel in session for call-id='%s'\n", call_id);

    return chan;
}

/* ---------- captured SIP coordinates (rdata has vanished by the time
 *            we send NOTIFY — so we snapshot everything up front) ------ */

struct park_sip_ctx {
    char target_uri[256];   /* phone's Contact URI  (Request-URI for NOTIFYs) */
    char from_uri[512];     /* our URI  (goes in From:)                      */
    char to_uri[512];       /* phone's URI (goes in To:)                     */
    char contact_uri[256];  /* our Contact                                    */
    char call_id[256];      /* REFER's Call-ID                                */
    char remote_tag[128];   /* phone's From-tag from the REFER                */
    char local_tag[128];    /* our To-tag that pjsip placed on our 202        */
    char local_host[128];   /* local transport IP (for dialog-info entity)    */
};

static int park_capture_sip_ctx(pjsip_rx_data *rdata, const pj_str_t *local_tag,
    struct park_sip_ctx *ctx)
{
    pjsip_msg *msg = rdata->msg_info.msg;
    pjsip_from_hdr *refer_from = rdata->msg_info.from;
    pjsip_to_hdr   *refer_to   = rdata->msg_info.to;
    pjsip_cid_hdr  *refer_cid  = rdata->msg_info.cid;
    pjsip_contact_hdr *refer_contact;
    pjsip_transport *tp = rdata->tp_info.transport;
    int n;

    memset(ctx, 0, sizeof(*ctx));

    if (!refer_from || !refer_to || !refer_cid || !tp) {
        ast_log(LOG_WARNING, "CiscoPark: REFER missing required headers\n");
        return -1;
    }

    refer_contact = (pjsip_contact_hdr *)pjsip_msg_find_hdr(msg,
        PJSIP_H_CONTACT, NULL);

    n = pjsip_uri_print(PJSIP_URI_IN_REQ_URI,
        refer_contact ? refer_contact->uri
                      : pjsip_uri_get_uri(refer_from->uri),
        ctx->target_uri, sizeof(ctx->target_uri) - 1);
    if (n <= 0) return -1;
    ctx->target_uri[n] = '\0';

    n = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, refer_to->uri,
        ctx->from_uri, sizeof(ctx->from_uri) - 1);
    if (n <= 0) return -1;
    ctx->from_uri[n] = '\0';

    n = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, refer_from->uri,
        ctx->to_uri, sizeof(ctx->to_uri) - 1);
    if (n <= 0) return -1;
    ctx->to_uri[n] = '\0';

    snprintf(ctx->contact_uri, sizeof(ctx->contact_uri),
        "<sip:%.*s:%d>",
        (int)tp->local_name.host.slen, tp->local_name.host.ptr,
        tp->local_name.port);

    ast_copy_string(ctx->call_id, "", sizeof(ctx->call_id));
    if (refer_cid->id.slen > 0) {
        int clen = (int)refer_cid->id.slen;
        if (clen >= (int)sizeof(ctx->call_id)) clen = sizeof(ctx->call_id) - 1;
        memcpy(ctx->call_id, refer_cid->id.ptr, clen);
        ctx->call_id[clen] = '\0';
    }

    if (refer_from->tag.slen > 0) {
        int tlen = (int)refer_from->tag.slen;
        if (tlen >= (int)sizeof(ctx->remote_tag)) tlen = sizeof(ctx->remote_tag) - 1;
        memcpy(ctx->remote_tag, refer_from->tag.ptr, tlen);
        ctx->remote_tag[tlen] = '\0';
    }

    if (local_tag && local_tag->slen > 0) {
        int tlen = (int)local_tag->slen;
        if (tlen >= (int)sizeof(ctx->local_tag)) tlen = sizeof(ctx->local_tag) - 1;
        memcpy(ctx->local_tag, local_tag->ptr, tlen);
        ctx->local_tag[tlen] = '\0';
    }

    {
        int hlen = (int)tp->local_name.host.slen;
        if (hlen >= (int)sizeof(ctx->local_host)) hlen = sizeof(ctx->local_host) - 1;
        memcpy(ctx->local_host, tp->local_name.host.ptr, hlen);
        ctx->local_host[hlen] = '\0';
    }

    return 0;
}

/* ---------- NOTIFY builder (with optional body) ----------------------- */

static void cisco_park_send_refer_notify(const struct park_sip_ctx *ctx,
    const char *subscription_state,
    const char *body_xml)     /* NULL or empty => Content-Length: 0 */
{
    static const pjsip_method notify_method = {
        PJSIP_OTHER_METHOD,
        { "NOTIFY", 6 }
    };
    pjsip_endpoint *endpt = ast_sip_get_pjsip_endpoint();
    pjsip_tx_data *tdata;
    pj_status_t status;
    pj_str_t target_s, from_s, to_s, contact_s, call_id_s;
    pj_str_t hname, hval;

    if (ctx->local_tag[0] == '\0') {
        ast_log(LOG_WARNING,
            "CiscoPark: cannot send NOTIFY (no local tag from 202)\n");
        return;
    }

    target_s.ptr  = (char *)ctx->target_uri;
    target_s.slen = (pj_ssize_t)strlen(ctx->target_uri);
    from_s.ptr    = (char *)ctx->from_uri;
    from_s.slen   = (pj_ssize_t)strlen(ctx->from_uri);
    to_s.ptr      = (char *)ctx->to_uri;
    to_s.slen     = (pj_ssize_t)strlen(ctx->to_uri);
    contact_s.ptr  = (char *)ctx->contact_uri;
    contact_s.slen = (pj_ssize_t)strlen(ctx->contact_uri);
    call_id_s.ptr  = (char *)ctx->call_id;
    call_id_s.slen = (pj_ssize_t)strlen(ctx->call_id);

    status = pjsip_endpt_create_request(endpt, &notify_method,
        &target_s, &from_s, &to_s, &contact_s,
        ctx->call_id[0] ? &call_id_s : NULL,
        -1, NULL, &tdata);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoPark: pjsip_endpt_create_request(NOTIFY) failed: %d\n", status);
        return;
    }

    {
        pj_str_t ltag = { (char *)ctx->local_tag,  (pj_ssize_t)strlen(ctx->local_tag)  };
        pj_str_t rtag = { (char *)ctx->remote_tag, (pj_ssize_t)strlen(ctx->remote_tag) };
        pjsip_from_hdr *f = (pjsip_from_hdr *)pjsip_msg_find_hdr(tdata->msg,
            PJSIP_H_FROM, NULL);
        pjsip_to_hdr   *t = (pjsip_to_hdr *)pjsip_msg_find_hdr(tdata->msg,
            PJSIP_H_TO,   NULL);
        if (f) pj_strdup(tdata->pool, &f->tag, &ltag);
        if (t && rtag.slen > 0) pj_strdup(tdata->pool, &t->tag, &rtag);
    }

    hname = pj_str("Event");
    hval  = pj_str("refer");
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    hname = pj_str("Subscription-State");
    hval.ptr  = (char *)subscription_state;
    hval.slen = (pj_ssize_t)strlen(subscription_state);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    if (body_xml && body_xml[0]) {
        pj_str_t ct_type    = pj_str("application");
        pj_str_t ct_subtype = pj_str("dialog-info+xml");
        pj_str_t body_str = { (char *)body_xml,
                              (pj_ssize_t)strlen(body_xml) };
        tdata->msg->body = pjsip_msg_body_create(tdata->pool,
            &ct_type, &ct_subtype, &body_str);
    }

    status = pjsip_endpt_send_request_stateless(endpt, tdata, NULL, NULL);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoPark: send_request_stateless(NOTIFY %s) failed: %d\n",
            subscription_state, status);
    } else {
        ast_log(LOG_NOTICE,
            "CiscoPark: sent NOTIFY %s\n", subscription_state);
    }
}

/* ---------- parking event listener ------------------------------------
 *
 * Per-park ephemeral subscription on ast_parking_topic().  We're looking
 * for a PARKED_CALL event whose parkee channel name matches the peer we
 * just redirected into the [cisco-park] context.  When it arrives we pull
 * the parking space (the slot number) and wake the worker thread via the
 * per-task cond var.
 */
struct park_task {
    struct park_sip_ctx ctx;
    char peer_name[AST_CHANNEL_NAME];
    char phone_name[AST_CHANNEL_NAME];

    /* Asterisk wraps pthread sync primitives with debug-thread
     * instrumentation; asterisk/lock.h poisons the raw pthread_*
     * names so we MUST use the ast_* wrappers here.  Semantics are
     * identical to POSIX. */
    ast_mutex_t mtx;
    ast_cond_t  cond;

    int  slot_known;
    unsigned int parking_space;
    char parkinglot[64];
};

static void park_stasis_cb(void *data, struct stasis_subscription *sub,
                            struct stasis_message *msg)
{
    struct park_task *task = data;
    struct ast_parked_call_payload *p;

    if (stasis_subscription_final_message(sub, msg)) {
        return;
    }
    if (stasis_message_type(msg) != ast_parked_call_type()) {
        return;
    }
    p = stasis_message_data(msg);
    if (!p || p->event_type != PARKED_CALL || !p->parkee || !p->parkee->base) {
        return;
    }
    if (strcmp(p->parkee->base->name, task->peer_name) != 0) {
        return;
    }

    ast_mutex_lock(&task->mtx);
    task->parking_space = p->parkingspace;
    ast_copy_string(task->parkinglot,
        p->parkinglot ? p->parkinglot : "default",
        sizeof(task->parkinglot));
    task->slot_known = 1;
    ast_cond_broadcast(&task->cond);
    ast_mutex_unlock(&task->mtx);
}

/* ---------- park worker thread ---------------------------------------- */

static void *cc_park_thread(void *data)
{
    struct park_task *t = data;
    struct ast_channel *ch_peer, *ch_phone;
    struct stasis_subscription *sub = NULL;
    char body_xml[1024];
    struct timespec ts;
    int wait_rc = 0;
    int phone_held_in_dialplan = 0;

    /* Subscribe BEFORE we redirect — a fast park can fire the event
     * before our worker gets on CPU. */
    sub = stasis_subscribe(ast_parking_topic(), park_stasis_cb, t);
    if (!sub) {
        ast_log(LOG_ERROR, "CiscoPark: could not subscribe to parking topic\n");
        goto done;
    }

    ast_log(LOG_NOTICE,
        "CiscoPark: parking peer '%s' (phone=%s)\n",
        t->peer_name, t->phone_name);

    /* ---- Redirect BOTH bridge members in a single tight burst.
     *
     * The phone and peer channels are Dial()-coupled: as soon as ONE
     * leaves the bridge, the OTHER side's Dial() returns and the peer
     * starts advancing through its post-bridge chain (h-extension ->
     * macro-hangupcall -> app-missedcall-hangup).  If our async_goto
     * on the peer doesn't land before that happens, the peer is
     * already flagged for hangup by the time res_parking places it
     * in the holding bridge — so Park() returns immediately, the
     * slot is released, and the caller hears the line drop.
     *
     * Fix (borrowed verbatim from the conference module, which fights
     * the exact same race): set up ALL side state UP FRONT, then fire
     * the two async_goto's back-to-back with no intervening locks,
     * hash lookups, or refcounts.  Redirect the callee (peer) first
     * and the caller (phone) second so Dial()'s "other side gone"
     * notice on the phone finds AST_FLAG_ASYNC_GOTO already set.
     *
     * Phone fallback: if [cisco-park-phone] isn't in the dialplan we
     * let the phone's post-bridge chain run and soft-hangup the phone
     * ourselves after the active NOTIFY has been transmitted. */
    int phone_exten_exists = ast_exists_extension(NULL,
            CISCO_PARK_PHONE_CONTEXT, CISCO_PARK_PHONE_EXTEN,
            CISCO_PARK_PHONE_PRIO, NULL);
    if (!phone_exten_exists) {
        ast_log(LOG_NOTICE,
            "CiscoPark: [%s] not defined in dialplan; NOTIFY may "
            "arrive after BYE on phone leg — add the context to "
            "extensions_custom.conf to fix\n",
            CISCO_PARK_PHONE_CONTEXT);
    }

    ch_peer  = ast_channel_get_by_name(t->peer_name);
    ch_phone = ast_channel_get_by_name(t->phone_name);

    if (!ch_peer) {
        ast_log(LOG_ERROR,
            "CiscoPark: peer channel '%s' gone before park\n", t->peer_name);
        if (ch_phone) ast_channel_unref(ch_phone);
        goto done;
    }

    /* Peer first — the callee/Dial'd leg must have AST_FLAG_ASYNC_GOTO
     * set before the phone's departure causes Dial() to cleanup. */
    if (ast_async_goto(ch_peer, CISCO_PARK_CONTEXT, CISCO_PARK_EXTEN,
                       CISCO_PARK_PRIO) != 0) {
        ast_log(LOG_ERROR,
            "CiscoPark: ast_async_goto(%s,%s,%s,%d) failed — is the "
            "[cisco-park] dialplan context defined?\n",
            t->peer_name, CISCO_PARK_CONTEXT, CISCO_PARK_EXTEN,
            CISCO_PARK_PRIO);
    }

    /* Phone second — immediately, with no intervening work. */
    if (ch_phone && phone_exten_exists) {
        if (ast_async_goto(ch_phone, CISCO_PARK_PHONE_CONTEXT,
                           CISCO_PARK_PHONE_EXTEN,
                           CISCO_PARK_PHONE_PRIO) == 0) {
            phone_held_in_dialplan = 1;
        } else {
            ast_log(LOG_WARNING,
                "CiscoPark: ast_async_goto(phone %s -> %s,%s,%d) "
                "failed; falling back to soft-hangup\n",
                t->phone_name, CISCO_PARK_PHONE_CONTEXT,
                CISCO_PARK_PHONE_EXTEN, CISCO_PARK_PHONE_PRIO);
        }
    }

    ast_channel_unref(ch_peer);
    if (ch_phone) ast_channel_unref(ch_phone);

    /* Wait for the parking stasis event that tells us the slot. */
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += CISCO_PARK_WAIT_SEC;

    ast_mutex_lock(&t->mtx);
    while (!t->slot_known && wait_rc == 0) {
        wait_rc = ast_cond_timedwait(&t->cond, &t->mtx, &ts);
    }
    ast_mutex_unlock(&t->mtx);

    if (!t->slot_known) {
        ast_log(LOG_WARNING,
            "CiscoPark: timed out waiting for park slot (%d s)\n",
            CISCO_PARK_WAIT_SEC);
        /* Still signal phone with terminated NOTIFY so the REFER
         * subscription closes and the softkey unlocks. */
        cisco_park_send_refer_notify(&t->ctx,
            "terminated;reason=noresource", NULL);
        goto done;
    }

    ast_log(LOG_NOTICE,
        "CiscoPark: peer parked at slot %u in '%s'\n",
        t->parking_space, t->parkinglot);

    /* Build dialog-info+xml body (CUCM park.txt frame 144).  entity=sip:<slot>@host
     * is what the Cisco phone extracts to show "Parked at <slot>". */
    snprintf(body_xml, sizeof(body_xml),
        "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\"\n"
        " xmlns:call=\"urn:x-cisco:params:xml:ns:dialog-info:dialog:callinfo-dialog\"\n"
        " version=\"1\" state=\"full\" entity=\"sip:%u@%s\">\n"
        " <dialog id=\"park\">\n"
        "  <state>confirmed</state>\n"
        "  <call:park>\n"
        "   <event>parked</event>\n"
        "  </call:park>\n"
        "  <local><identity display=\"\">sip:%u@%s</identity></local>\n"
        "  <remote><identity display=\"\">sip:parked@%s</identity></remote>\n"
        " </dialog>\n"
        "</dialog-info>\n",
        t->parking_space, t->ctx.local_host,
        t->parking_space, t->ctx.local_host,
        t->ctx.local_host);

    cisco_park_send_refer_notify(&t->ctx, "active;expires=3600", body_xml);

    /* If we couldn't route the phone into [cisco-park-phone] earlier,
     * fall back to soft-hanging up the phone leg ourselves.  Otherwise
     * the Wait(1) + Hangup() in the dialplan will finish the leg and
     * our NOTIFY will have arrived first. */
    if (!phone_held_in_dialplan) {
        struct ast_channel *ch_fallback =
            ast_channel_get_by_name(t->phone_name);
        if (ch_fallback) {
            ast_softhangup(ch_fallback, AST_SOFTHANGUP_DEV);
            ast_channel_unref(ch_fallback);
        }
    }

    /* Give the phone a moment to process the active NOTIFY before we
     * close the refer subscription. */
    usleep(500000);

    snprintf(body_xml, sizeof(body_xml),
        "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\"\n"
        " xmlns:call=\"urn:x-cisco:params:xml:ns:dialog-info:dialog:callinfo-dialog\"\n"
        " version=\"2\" state=\"full\" entity=\"sip:%u@%s\">\n"
        " <dialog id=\"park\">\n"
        "  <state>terminated</state>\n"
        " </dialog>\n"
        "</dialog-info>\n",
        t->parking_space, t->ctx.local_host);

    cisco_park_send_refer_notify(&t->ctx,
        "terminated;reason=noresource", body_xml);

done:
    if (sub) {
        stasis_unsubscribe_and_join(sub);
    }
    ast_mutex_destroy(&t->mtx);
    ast_cond_destroy(&t->cond);
    ast_free(t);
    return NULL;
}

/* ---------- PJSIP receive callback ------------------------------------ */

static pj_bool_t cisco_park_on_rx_request(pjsip_rx_data *rdata)
{
    pjsip_msg *msg = rdata->msg_info.msg;
    pjsip_tx_data *resp;
    char body[8192], event[64], section[2048];
    char dlg_callid[256], dlg_ltag[128], dlg_rtag[128];
    const char *p, *q;
    size_t slen;
    int blen;
    struct ast_channel *ch_phone, *ch_peer;
    struct park_task *task;
    pthread_attr_t attr;
    pthread_t thr;

    if (pjsip_method_cmp(&msg->line.req.method, &pjsip_refer_method) != 0)
        return PJ_FALSE;
    if (!msg->body || !msg->body->data || !msg->body->len)
        return PJ_FALSE;

    if (pj_stricmp2(&msg->body->content_type.type,    "application") != 0 ||
        pj_stricmp2(&msg->body->content_type.subtype, "x-cisco-remotecc-request+xml") != 0)
        return PJ_FALSE;

    blen = (int)msg->body->len < (int)(sizeof(body) - 1)
           ? (int)msg->body->len : (int)(sizeof(body) - 1);
    memcpy(body, msg->body->data, blen);
    body[blen] = '\0';

    if (xml_get(body, "softkeyevent", event, sizeof(event)) != 0)
        return PJ_FALSE;

    if (strcasecmp(event, "ParkMonitor") != 0) {
        /* Not ours. */
        return PJ_FALSE;
    }

    p = strstr(body, "<dialogid>");
    q = strstr(body, "</dialogid>");
    if (!p || !q) goto malformed;
    slen = (size_t)(q - p) + strlen("</dialogid>");
    if (slen >= sizeof(section)) slen = sizeof(section) - 1;
    memcpy(section, p, slen); section[slen] = '\0';

    if (xml_get(section, "callid",    dlg_callid, sizeof(dlg_callid)) ||
        xml_get(section, "localtag",  dlg_ltag,   sizeof(dlg_ltag))   ||
        xml_get(section, "remotetag", dlg_rtag,   sizeof(dlg_rtag)))
        goto malformed;

    ast_log(LOG_NOTICE, "CiscoPark: ParkMonitor REFER — call-id='%s'\n",
        dlg_callid);

    ch_phone = channel_for_dialog(dlg_callid, dlg_ltag, dlg_rtag);
    if (!ch_phone) goto lookup_fail;

    ch_peer = ast_channel_bridge_peer(ch_phone);
    if (!ch_peer) {
        ast_log(LOG_ERROR,
            "CiscoPark: no bridge peer for '%s' — nothing to park\n",
            ast_channel_name(ch_phone));
        ast_channel_unref(ch_phone);
        goto lookup_fail;
    }

    task = ast_calloc(1, sizeof(*task));
    if (!task) {
        ast_channel_unref(ch_phone);
        ast_channel_unref(ch_peer);
        goto lookup_fail;
    }
    ast_mutex_init(&task->mtx);
    ast_cond_init(&task->cond, NULL);

    ast_copy_string(task->phone_name, ast_channel_name(ch_phone),
        sizeof(task->phone_name));
    ast_copy_string(task->peer_name,  ast_channel_name(ch_peer),
        sizeof(task->peer_name));

    ast_channel_unref(ch_phone);
    ast_channel_unref(ch_peer);

    /* ---- send 202 Accepted -----------------------------------------
     *
     * pjsip_endpt_create_response auto-generates a stateless To-tag that
     * is derived from the incoming Via branch; functional but predictable.
     * Overwrite it with a fresh random string so the NOTIFY subscription
     * dialog has a proper random local tag. */
    char local_tag_buf[33] = "";
    pj_str_t local_tag = { NULL, 0 };

    if (pjsip_endpt_create_response(ast_sip_get_pjsip_endpoint(),
            rdata, 202, NULL, &resp) == PJ_SUCCESS) {
        pjsip_to_hdr *to_h = (pjsip_to_hdr *)pjsip_msg_find_hdr(
            resp->msg, PJSIP_H_TO, NULL);
        if (to_h) {
            pj_str_t newtag;
            newtag.ptr  = local_tag_buf;
            newtag.slen = 32;
            pj_create_random_string(local_tag_buf, 32);
            local_tag_buf[32] = '\0';
            pj_strdup(resp->pool, &to_h->tag, &newtag);

            local_tag.ptr  = local_tag_buf;
            local_tag.slen = 32;
        }
        pjsip_endpt_send_response2(ast_sip_get_pjsip_endpoint(),
            rdata, resp, NULL, NULL);
    } else {
        ast_log(LOG_ERROR, "CiscoPark: could not create 202 response\n");
    }

    if (park_capture_sip_ctx(rdata, &local_tag, &task->ctx) != 0) {
        ast_log(LOG_ERROR, "CiscoPark: could not snapshot SIP ctx\n");
        ast_mutex_destroy(&task->mtx);
        ast_cond_destroy(&task->cond);
        ast_free(task);
        return PJ_TRUE;
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thr, &attr, cc_park_thread, task) != 0) {
        ast_log(LOG_ERROR, "CiscoPark: pthread_create failed\n");
        ast_mutex_destroy(&task->mtx);
        ast_cond_destroy(&task->cond);
        ast_free(task);
    }
    pthread_attr_destroy(&attr);

    return PJ_TRUE;

malformed:
    ast_log(LOG_WARNING, "CiscoPark: malformed x-cisco-remotecc body\n");
    if (pjsip_endpt_create_response(ast_sip_get_pjsip_endpoint(),
            rdata, 400, NULL, &resp) == PJ_SUCCESS)
        pjsip_endpt_send_response2(ast_sip_get_pjsip_endpoint(),
            rdata, resp, NULL, NULL);
    return PJ_TRUE;

lookup_fail:
    ast_log(LOG_ERROR, "CiscoPark: channel lookup failed; park aborted\n");
    if (pjsip_endpt_create_response(ast_sip_get_pjsip_endpoint(),
            rdata, 500, NULL, &resp) == PJ_SUCCESS)
        pjsip_endpt_send_response2(ast_sip_get_pjsip_endpoint(),
            rdata, resp, NULL, NULL);
    return PJ_TRUE;
}

/* ---------- module registration --------------------------------------- */

static pjsip_module cisco_park_pjsip_module = {
    .name     = { "mod-cisco-park", 15 },
    /*
     * Lower = higher priority.  res_pjsip_cisco_conference sits at
     * APPLICATION-1 (31) and consumes *all* x-cisco-remotecc REFERs —
     * silently 200-OK'ing any softkey it doesn't recognise (including
     * ParkMonitor).  We therefore register at APPLICATION-2 (30) so we
     * see the REFER first; if the event isn't ours we return PJ_FALSE
     * and the conference module gets it next.
     */
    .priority = PJSIP_MOD_PRIORITY_APPLICATION - 2,
    .on_rx_request = cisco_park_on_rx_request,
};

static int load_module(void)
{
    if (ast_sip_register_service(&cisco_park_pjsip_module)) {
        ast_log(LOG_ERROR, "CiscoPark: failed to register PJSIP service\n");
        return AST_MODULE_LOAD_DECLINE;
    }
    ast_log(LOG_NOTICE, "CiscoPark: Cisco park module loaded\n");
    return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
    ast_sip_unregister_service(&cisco_park_pjsip_module);
    return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT,
    "Cisco x-cisco-remotecc Park Handler",
    .support_level = AST_MODULE_SUPPORT_EXTENDED,
    .load   = load_module,
    .unload = unload_module,
    .requires = "res_pjsip,res_pjsip_session,res_parking",
);
