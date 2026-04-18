# res_pjsip_cisco_park

An Asterisk PJSIP module that makes the **Park soft key** on Cisco CP-8xxx IP phones work with FreePBX / Asterisk 21, including displaying the reserved parking slot on the phone's screen.

---

## The problem

When the user presses the Park soft key, Cisco CP-8xxx phones (CP-8811, CP-8841, CP-8851, CP-8861 ...) send a `REFER` request carrying a proprietary body:

```xml
REFER sip:pbx SIP/2.0
Content-Type: application/x-cisco-remotecc-request+xml

<?xml version="1.0" encoding="UTF-8"?>
<x-cisco-remotecc-request>
  <softkeyeventmsg>
    <softkeyevent>ParkMonitor</softkeyevent>
    <dialogid>
      <callid>…</callid>
      <localtag>…</localtag>
      <remotetag>…</remotetag>
    </dialogid>
  </softkeyeventmsg>
</x-cisco-remotecc-request>
```

Asterisk has no built-in handler for this content type and normally responds `501 Not Implemented`.

This module intercepts those `REFER` messages, uses the embedded SIP dialog identifiers to locate the active call, parks the remote party into Asterisk's `res_parking` lot, and signals the Cisco phone with a `NOTIFY` message containing an `application/dialog-info+xml` payload. This payload instructs the phone to display the assigned parking slot (e.g., "Parked at 71") and elegantly terminates the call leg.

---

## Requirements

| Component | Version tested |
|---|---|
| OS | Debian / Ubuntu (FreePBX 17 ISO) |
| FreePBX | 17 |
| Asterisk | 21.5.0 |
| Asterisk source (headers only) | 21.12.2 |
| GCC | 12+ (system default) |
| Cisco phones | CP-8811 |

*Note: Requires Asterisk's standard `res_parking` module to be loaded.*

---

## Installation

### Step 1 — Install build tools

```bash
apt-get update
apt-get install -y gcc make wget tar \
    libssl-dev libncurses5-dev uuid-dev \
    libjansson-dev libxml2-dev libsqlite3-dev \
    libedit-dev binutils
```

### Step 2 — Download the Asterisk source tree

The source tree is needed **for headers only** — you do not recompile Asterisk.
Use the closest available version to what FreePBX installed (21.12.2 works fine with 21.5.0):

```bash
cd /usr/src
wget https://downloads.asterisk.org/pub/telephony/asterisk/asterisk-21.12.2.tar.gz
tar xzf asterisk-21.12.2.tar.gz
```

Run `./configure` to generate `autoconfig.h` and unpack the bundled pjproject headers:

```bash
cd /usr/src/asterisk-21.12.2
./configure --with-pjproject-bundled
```

> You do **not** need to run `make` for Asterisk itself.

### Step 3 — Create `buildopts.h`

Asterisk enforces a build-option checksum between a module and the running binary.
Extract the checksum from the already-installed `res_pjsip.so`:

Write the header:

```bash
BUILDSUM=$(strings /usr/lib/x86_64-linux-gnu/asterisk/modules/res_pjsip.so \
    | grep -E "^[a-f0-9]{32}$" | head -1)
echo "Found checksum: $BUILDSUM"

cat > /usr/src/asterisk-21.12.2/include/asterisk/buildopts.h <<EOF
#ifndef _ASTERISK_BUILDOPTS_H
#define _ASTERISK_BUILDOPTS_H

#if defined(HAVE_COMPILER_ATTRIBUTE_WEAKREF)
#define __ref_undefined __attribute__((weakref));
#else
#define __ref_undefined ;
#endif

#define AST_BUILDOPT_SUM "${BUILDSUM}"

#endif /* _ASTERISK_BUILDOPTS_H */
EOF
```

Verify:

```bash
cat /usr/src/asterisk-21.12.2/include/asterisk/buildopts.h
```

### Step 4 — Copy the source file

```bash
cp res_pjsip_cisco_park.c /usr/src/asterisk-21.12.2/res/
```

### Step 5 — Compile

```bash
ASTSRC=/usr/src/asterisk-21.12.2
MODDIR=/usr/lib/x86_64-linux-gnu/asterisk/modules
PJROOT=${ASTSRC}/third-party/pjproject/source

gcc -fPIC -shared -g -O2 \
  -DASTERISK_REGISTER_FILE \
  -D_GNU_SOURCE \
  -DAST_MODULE_SELF_SYM=__local_ast_module_self \
  -DAST_MODULE=\"res_pjsip_cisco_park\" \
  -I${ASTSRC}/include \
  -I${PJROOT}/pjsip/include \
  -I${PJROOT}/pjlib/include \
  -I${PJROOT}/pjlib-util/include \
  -I${PJROOT}/pjmedia/include \
  -I${PJROOT}/pjnath/include \
  -o ${MODDIR}/res_pjsip_cisco_park.so \
  ${ASTSRC}/res/res_pjsip_cisco_park.c \
  && echo "COMPILE OK"
```

A successful build prints `COMPILE OK` and may produce a few harmless warnings. No errors.

### Step 6 — Load the module

```bash
asterisk -rx "module load res_pjsip_cisco_park.so"
asterisk -rx "module show like cisco_park"
```

Expected output:

```text
Module                             Description                              Use Count  Status      Support Level
res_pjsip_cisco_park.so            Cisco x-cisco-remotecc Park Handler      0          Running     extended
```

#### Auto-load on restart

FreePBX's `modules.conf` uses `autoload=yes` by default, which means every `.so` placed in the modules directory loads automatically on startup. No further configuration is needed.

### Step 7 — Dialplan

Add the required contexts to `/etc/asterisk/extensions_custom.conf`:

```ini
[cisco-park]
exten => s,1,NoOp(Cisco Park peer ${CHANNEL})
 same => n,Park(default,s,60)
 same => n,Hangup()

[cisco-park-phone]
exten => s,1,NoOp(Cisco Park phone leg ${CHANNEL})
 same => n,Wait(1)
 same => n,Hangup()
```

Reload the dialplan:

```bash
asterisk -rx "dialplan reload"
```

---

## How it works

1. **Intercept REFER:** The module listens at priority `30` (`PJSIP_MOD_PRIORITY_APPLICATION - 2`) for incoming REFER requests. By running just before `res_pjsip_refer` (32) and other application modules, it can intercept `<softkeyevent>ParkMonitor</softkeyevent>`.
2. **Accept Request:** It sends a `202 Accepted` back to the phone.
3. **Bridge Redirection:** A background thread reads the targeted bridge and uses `ast_async_goto` to synchronously redirect both parties:
   - The *peer* is redirected to `[cisco-park]` and executes `Park()`.
   - The *phone* is redirected to `[cisco-park-phone]` and sits in a short `Wait(1)`. This keeps the channel alive just long enough to receive the `NOTIFY` response before hanging up, bypassing FreePBX's missed-call post-bridge routines.
4. **Stasis Event Monitor:** The worker thread listens on `ast_parking_topic()` for the `PARKED_CALL` event matching the newly parked peer, learning its parking space index (e.g. 71).
5. **NOTIFY to Phone:** A sip `NOTIFY` containing `application/dialog-info+xml` is blasted back to the phone with `<event>parked</event>` and `entity="sip:71@host"`, natively triggering the phone interface to display "Parked at 71". A termination notify follows to unlock the phone's softkey state.

---

## Troubleshooting

### Verify Module Execution

Check the Asterisk log while pressing the Park button:

```bash
tail -f /var/log/asterisk/full | grep -E "CiscoPark|res_pjsip_cisco_park.c"
```

Good output will look like:
```text
NOTICE[...] res_pjsip_cisco_park.c: CiscoPark: ParkMonitor REFER — call-id='...'
NOTICE[...] res_pjsip_cisco_park.c: CiscoPark: parking peer '...' (phone=...)
NOTICE[...] res_pjsip_cisco_park.c: CiscoPark: peer parked at slot 71 in 'default'
NOTICE[...] res_pjsip_cisco_park.c: CiscoPark: sent NOTIFY active;expires=3600
NOTICE[...] res_pjsip_cisco_park.c: CiscoPark: sent NOTIFY terminated;reason=noresource
```

### Missing [cisco-park-phone] Context Warning

If you see:
`CiscoPark: [cisco-park-phone] not defined in dialplan; NOTIFY may arrive after BYE on phone leg`

This means you forgot to add the `[cisco-park-phone]` context in step 7. Without it, the module performs a software hangup internally, which risks disconnecting the line *before* the notification packet is received by the phone, preventing the visual park slot from displaying on the screen.

### Park Fails / Caller Dropped

If you see `CiscoPark: timed out waiting for park slot` in the logs, it means the peer couldn't be parked properly within 3 seconds. Check:
- Is `res_parking` loaded and configured in FreePBX?
- Are the `[cisco-park]` dialplan instructions reachable? Verify with `asterisk -rx "dialplan show cisco-park"`.
