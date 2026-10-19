# Danfoss Link CC → Home Assistant, without the vendor app

A native Linux client for the Danfoss Link CC central controller. It speaks the
CC's own cloud protocol (Trifork SecureDeviceGrid, "MDG"), so Home Assistant can
pause and resume heating over MQTT. No Android emulator, no UI automation, no
vendor binaries at runtime.

Status: **live.** The peer is paired with the CC and the full path works; Home
Assistant pauses/resumes heating and controls per-room setpoints. The peer and
the bridge run as one container (`dlre-helper`).

```
Home Assistant ──MQTT──► bridge (Python) ──HTTP──► peer (Lua + MDG stack)
                                                      │ TLS 1.2, client cert
                                                      ▼
                                          mdg-danfoss.hosted.trifork.com:443
                                                      │ routed call, protocol "cc_json"
                                                      ▼
                                              Danfoss Link CC → REST /api/...
```

## How this works

The Danfoss Link app is a thin Java wrapper around a **Lua** implementation of
the MDG protocol: `luafiles/mdg-c.zip` inside the APK holds the entire stack as
Lua 5.1 bytecode, and `libluavm-java.so` is Lua 5.1.4 plus patched LuaSocket,
LuaSec 0.5, protoc-gen-lua, OpenSSL 1.0.2 and some Trifork crypto modules.

So this project runs **the vendor's own Lua code** on stock Lua 5.1, with
replacements for the native modules:

| Vendor native module | Replacement |
|---|---|
| `socket`, `mime`, `ssl` | LuaRocks LuaSocket 3.x + LuaSec 1.3 (`peer/shim/mdgcompat.lua` bridges the 0.5 → 1.3 differences) |
| `pb` | upstream protoc-gen-lua `pb.c` (identical API) |
| `struct`, `lpeg` | upstream rocks |
| `fileops`, `osmisc` | `peer/shim/*.lua` |
| `lbn`, `ecgroup`, `ecpoint`, `crypto`, `cryptomisc` | `work/dlrenative.c` — OpenSSL BN/EC/EVP behind the vendor ABI |

`peer/main.lua` replaces Trifork's `lush` bootstrap (`android_main.lua`,
`cc_main.lua`), builds the peer config and starts the stack.

Protocol details — framing, message catalogue, PACE, the CC's REST surface, the
bytecode format and the native module ABI — are in
[`docs/protocol.md`](docs/protocol.md).

### Things that had to be reverse engineered

1. **Bytecode format.** The `.luac` files report Lua format `204`: standard
   Lua 5.1 chunks whose ints and size_ts are big-endian 7-bit varints, with
   debug info stripped. `tools/luac204.py` converts them to standard chunks
   (and injects chunk names so tracebacks are readable). `android_main.lua`
   ships as both source and bytecode, which made a clean cross-check possible.
2. **Peer identity.** An MDG peer id is the lowercase hex **Subject Key
   Identifier** of its certificate, derived in `mdg.lua` via
   `ssl.x509.load(pem):subject_key_identifier()`. Modern LuaSec has no such
   method, so `peer/shim/mdgcompat.lua` adds it. The grid's routed call
   (`place_call`) addresses a peer by that id in **colon-separated hex**
   (`aa:bb:…`), not plain hex; `peer/shim/dlre_ccapi.lua` converts it before
   calling.
3. **TLS.** The grid and the CC use ECDSA certificates on **brainpoolP320r1**
   with *explicit* curve parameters. That curve was never registered as a TLS
   group (RFC 7027 covers 256/384/512 only), so:
   - OpenSSL ≥ 1.1.0 rejects the peer signature algorithm
     (`tls12_check_peer_sigalg`: "wrong curve");
   - OpenSSL 3 additionally fails chain verification with error 94
     ("explicit ECC parameters") and cannot be told otherwise.

   OpenSSL 1.0.2, which the app ships, performed neither check. The runtime
   therefore builds **OpenSSL 1.1.1w with that one TLS-1.2 check disabled**
   (`work/build-openssl.sh`) and links only LuaSec against it; the rest of the
   image uses the distro OpenSSL 3. Chain verification stays on, and
   `peer/shim/mdgpin.lua` additionally pins the CA certificate shipped in the
   APK.
4. **CC application protocol.** Over an MDG call with protocol `cc_json`, peers
   exchange length-prefixed (2-byte) JSON frames that tunnel a REST call:

   ```json
   {"id":1,"data":{"type":"JsonWebRequest",
     "data":{"method":"PUT","uri":"/api/modes/pause",
             "headers":["Accept: application/json; charset=utf-8"],
             "content":{"type":"Pause","state":"Active"}}}}
   ```

   The reply is a `JsonWebResponse` with the same id. The CC's REST surface, as
   used by the app: `/api/modes`, `/api/rooms`, `/api/onoffdevices`,
   `/api/settings/temperature`, `/api/system/{status,info,apiversions}`,
   `/api/alarms`, `/api/zones/living`. House modes are `AtHome`, `Vacation`,
   `Pause`, `Boost`, each with state `Active`/`Inactive` — pausing heating is
   `PUT /api/modes/pause {"type":"Pause","state":"Active"}`.

## Layout

| Path | What |
|---|---|
| `docker-compose.yml`, `Dockerfile.helper`, `entrypoint.sh` | one `dlre-helper` service — peer + bridge in one container |
| `peer/main.lua` | peer bootstrap and config |
| `peer/shim/` | replacements and compatibility patches, plus `dlre_ccapi.lua` (the CC REST client) |
| `peer/lua/` | vendor Lua bytecode, converted (generated by `tools/layout.sh`) |
| `peer/data/` | identity (`app_key.pem`, `app_cert.pem`) and `pairings/` — **the state that matters** |
| `bridge/mqtt_bridge.py` | MQTT ↔ peer HTTP, Home Assistant discovery |
| `homeassistant/` | HA automations + scripts: mains-outage pause/unpause, schedule restore on resume |
| `work/` | build inputs: runtime Dockerfile, OpenSSL patch script, `dlrenative.c` |
| `tools/luac204.py` | format-204 → standard Lua 5.1 bytecode |
| `tools/layout.sh` | assembles `peer/lua` from converted bytecode |
| `tools/pair.sh` | one-time pairing helper |
| `out/lua_src/` | decompiled vendor Lua, for reading (not runnable: upvalue names are lost) |
| `out/jadx/` | decompiled app, for reading |
| `docs/protocol.md` | protocol reference recovered from the app |

## Run it

```sh
cp .env.example .env                                       # MQTT host, user, password
docker build -t dlre-run -f work/Dockerfile.runtime work/  # peer base image
docker compose up -d --build                               # dlre-helper (peer + bridge)
curl -s localhost:20558/whoami   # {"device_id":"<40 hex>","name":"dlre-bridge"}
curl -s localhost:20558/status   # connected_to_mdg should become true
```

The peer identity is generated once:

```sh
docker compose exec dlre-helper sh -c 'cd /peer/data && \
  openssl ecparam -name brainpoolP320r1 -genkey -noout -out app_key.pem && \
  openssl req -new -x509 -key app_key.pem -sha256 -days 3650 \
    -subj "/CN=dlre-bridge" -out app_cert.pem'
```

Back up `peer/data/` — losing it means pairing again.

### Pairing

Pairing is a one-time PACE exchange authenticated by a 5-digit OTP from the CC,
and it needs the CC in pairing mode:

1. On the CC: allow app access / pairing. It shows a 5-digit code.
2. `tools/pair.sh 12345` (grid pairing), or `tools/pair.sh 12345 192.168.1.50`
   for LAN pairing if the CC is on the same network.
3. `curl -s localhost:20558/pairings` should list the CC's device id.

Then the control path is live:

```sh
curl -s 'localhost:20558/cc-request?method=GET&uri=/api/modes'
curl -s 'localhost:20558/cc-pause?state=Active'     # pause heating
curl -s 'localhost:20558/cc-pause?state=Inactive'   # resume
```

Home Assistant gets, via MQTT discovery: a `switch` for house pause, a
connectivity diagnostic `binary_sensor`, and one `climate` entity per room
(current temperature + writable setpoint). Raw payloads are also published on
`danfoss-link/modes` and `danfoss-link/rooms`.

## Notes

- **LAN path.** The CC's LAN listener (port 14641) is not bound on firmware
  4.2.1797, so only the grid path works. `place-call-local` / `pair-local` are
  wired up for a LAN-visible CC; that path would remove the cloud dependency.
- The peer also listens on 14641 itself; `enable_mdns` is off by default.
- Routing depends on Danfoss's cloud (the grid). For fully-local control Danfoss
  recommends migrating to Ally (Zigbee).
- PACE pairing is cross-checked by `peer/selftest_pace.lua`, which runs the
  vendor client and server halves against each other.

## Tooling

Runtime (`work/Dockerfile.runtime`, `Dockerfile.helper`):

- Docker + Docker Compose.
- Lua 5.1 + LuaRocks: LuaSocket, LuaSec, `struct`, luafilesystem, lpeg.
- OpenSSL **1.1.1w**, built from source with one TLS-1.2 check disabled
  (`work/build-openssl.sh`; source: <https://github.com/openssl/openssl>, tag
  `OpenSSL_1_1_1w`). Only LuaSec links against it; the rest uses distro OpenSSL 3.
- `pb` from protoc-gen-lua.
- Python 3 + `paho-mqtt` 2.1.0 (the bridge).

Reverse-engineering / asset prep (`work/Dockerfile.tools`):

- **jadx 1.5.1** — APK/dex decompiler.
- **unluac** — Lua 5.1 decompiler (built from source).
- `tools/luac204.py` converts Trifork "format 204" bytecode to standard Lua 5.1;
  `tools/layout.sh` assembles `peer/lua`; `tools/pair.sh` pairs with the CC.

Home Assistant side: Home Assistant + an MQTT broker (Mosquitto). Entities are
created via MQTT discovery; no custom component.

## Reproducing this, and prior work

Rebuilding the peer needs the vendor assets, which are **not** in this repo (see
Legal); get them from your own install:

- The **Danfoss Link app** APK carries the Lua MDG stack (`luafiles/mdg-c.zip`),
  the native lib and the CA cert. Unpack with `jadx`/`unzip`, convert the
  bytecode with `tools/luac204.py`, lay it out with `tools/layout.sh`.
- The peer identity and CC pairing are generated locally (see [Run it](#run-it)
  and [Pairing](#pairing)).

Built on prior work — credit to the authors:

- **Trifork — Secure Device Grid ("MDG")**, the protocol this speaks, and its
  reference SDK: <https://github.com/trifork/secure-device-grid>.
- **Ole-JH — `ha-danfoss-link`**, a pure-Python MDG client used to cross-check
  the protocol, the `cc_json`/REST surface and the colon-hex `peer_name`:
  <https://github.com/Ole-JH/ha-danfoss-link>.
- **sean-lin — protoc-gen-lua** (`pb`): <https://github.com/sean-lin/protoc-gen-lua>.
- **skylot — jadx**: <https://github.com/skylot/jadx>.
- **HansWessels — unluac**: <https://github.com/HansWessels/unluac>.
- The **OpenSSL**, **LuaSec** and **LuaSocket** projects.

## Legal

Personal interoperability work on hardware I own. The vendor's Lua bytecode,
certificates and keys stay local: only build inputs and my own code are in this
repository. Don't redistribute the extracted vendor files.
