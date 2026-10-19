# Danfoss Link CC over SecureDeviceGrid — protocol notes

Everything here was recovered from `com.danfoss.linkapp` 1.3.10: the Lua stack in
`luafiles/mdg-c.zip` (Trifork's MDG client, Lua 5.1 bytecode) and the app's own
Kotlin/Java in `classes.dex`. File references point at the decompiled trees
under `out/lua_src/` and `out/jadx/` (both git-ignored, regenerate locally).

Nothing in this document came from Trifork or Danfoss documentation; treat it as
observed behaviour, not spec.

## 1. Layers

```
TCP 443  ─► TLS 1.2, mutual certs          grid: mdg-danfoss.hosted.trifork.com
           │
           ├─ MDG control protocol         protobuf, 2-byte length framing
           │  handshake / ping / place_call / allocate_pairing_channel
           │
           └─ per-call routed stream       mdg.routing.Handshake{token} → GoAhead
              │
              └─ application protocol      selected by name, e.g. "cc_json"
                 └─ cc_json                2-byte framed JSON tunnelling REST
```

Every stream in the stack uses the same framing: `cotcp.setopt(sock, {packet = 2})`,
i.e. a 2-byte big-endian length prefix per message (`mdg_comm_strategy.lua`,
`mdg_lan_comm.lua`, `mdg_multiplexer.lua`, `cc_json.lua`).

A peer is either a `controller` (the app, and this project) or a `thing` (the
CC). Roles gate the operation interface, see §7.

## 2. Identity

- A peer identity is a self-signed **EC certificate on brainpoolP320r1**
  (`luafiles/brainpoolP320r1-curve.pem` carries the explicit curve parameters;
  `ec.lua` holds the same `p/a/b/x/y/q/h` as hex constants).
- The **peer id** (`peer_name` on the wire, `device_id` in the app) is the
  lowercase hex **Subject Key Identifier** of that certificate — SHA-1 over the
  public key BIT STRING, 40 hex chars. `mdg.lua`:
  `peer_id = ssl.x509.load(cert):subject_key_identifier()`.
- The app stores its identity as `app_key.pem` / `app_cert.pem` in the app data
  dir (`android_main.lua`); the CC uses `certificate.key` / `certificate.crt`
  (`cc_main.lua`). This project keeps them in `peer/data/`.
- Pairings live as one file per peer under `<datadir>/pairings/`, named after the
  peer id with `:` replaced by `_`, serialised by `savetable.lua`
  (`mdg_pairing_db.lua`).

## 3. TLS

Parameters the stack sets (`mdg_init.lua` defaults, consumed by `ssl.newcontext`):

| Field | Value |
|---|---|
| `protocol` | `tlsv1_2` |
| `cipher` | `ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA` |
| `curve` | `brainpoolP320r1` |
| `cafile` | `luafiles/trusted-CAs.pem` — one cert, `C=DK, L=Aarhus, O=Trifork A/S, CN=MDG CA` |
| `verify` | `peer` |

Observed server identity: `C=DK, O=Trifork A/S, CN=MDG Control v2`, issued by
`MDG CA`. Negotiated in practice: `TLSv1.2 ECDHE-ECDSA-AES256-GCM-SHA384`.

Grid endpoints (`mdg_init.lua`): DNS `mdg-danfoss.hosted.trifork.com` plus
hardcoded `77.66.11.90`, `77.66.11.92`, `5.179.92.180`, `5.179.92.182` and IPv6
equivalents, all on port 443. Remote logging target (unused here):
`77.66.11.94:9999`.

### Why stock OpenSSL cannot do this

Trifork's certificates put brainpoolP320r1 in the key *with explicit curve
parameters*. Two independent checks in modern OpenSSL reject that:

| OpenSSL | Failure | Note |
|---|---|---|
| ≥ 1.1.0 | `tls12_check_peer_sigalg`: `SSL_R_WRONG_CURVE` | TLS 1.2 requires an ECDSA cert's curve to be an advertised group; brainpoolP320r1 was never registered as a TLS group — RFC 7027 defines only 256/384/512 |
| ≥ 3.0 | verify error 94, `X509_V_ERR_EC_KEY_EXPLICIT_PARAMS` | no flag disables it; also brainpool groups cannot be set at all (`group 'brainpoolP320r1' cannot be set`) |

The app shipped OpenSSL 1.0.2s, which performed neither check. This project
builds OpenSSL 1.1.1w with the TLS-1.2 group check disabled
(`work/build-openssl.sh`, one `if (0)`) and links only LuaSec against it. Chain
verification against the bundled CA stays enabled, and `peer/shim/mdgpin.lua`
pins that CA certificate as a second gate.

## 4. Control protocol

Protobuf over the TLS stream, 2-byte framed, messages tagged by
`mdg.control.control_message_tag`. Handshake magic is `0xF09D8CA8`
(`4036857000`, `mdg_control_protocol.lua`).

```proto
message handshake {
  required fixed32 magic = 1;          // 0xF09D8CA8
  required uint32 version_major = 2;
  required uint32 version_minor = 3;
  repeated property property = 4;      // key/value strings
}

message place_call {
  required uint32 req_id = 1;
  required string peer_name = 2;       // target peer id (40 hex)
  optional string protocol = 3;        // e.g. "cc_json"
  optional string ticket = 4;
}

message place_call_reply {
  required uint32 req_id = 1;
  required place_call_result result = 2;
  optional routing_info routing = 3;
  optional string result_text = 4;
}

message routing_info {
  required string peer_name = 3;
  repeated endpoint router = 4;        // host (bytes) + port
  required bytes token = 5;            // presented on the routed stream
}

message incoming_call {
  required uint32 req_id = 1;
  required routing_info routing = 2;
  optional string protocol = 3;
  optional string ticket = 4;
}
message incoming_call_reply { required uint32 req_id = 1; required bool will_accept_call = 2; }

message ping       { required uint32 req_id = 1; optional uint32 perceived_qos = 2; }
message ping_reply { required uint32 req_id = 1; }
message reconnect  { optional endpoint new_host = 1; optional uint32 suggested_delay = 2; }
message bye        { required bye_reason reason = 1; optional string reason_text = 2; }

// pairing rendezvous, see §6
message allocate_pairing_channel       { required uint32 req_id = 1; }
message allocate_pairing_channel_reply { required uint32 req_id = 1;
                                         required allocate_pairing_channel_result result = 2;
                                         optional string pair_id = 3;
                                         optional uint64 end_of_validity = 4; }
message place_pairing_call             { required uint32 req_id = 1; required string pair_id = 2; }
message incoming_pairing_call          { required uint32 req_id = 1; required routing_info routing = 2;
                                         required string pair_id = 3; }
message set_peer_whitelist             { required uint32 req_id = 1; repeated string peer_name = 2; }
```

Ping interval seen at runtime: `timeout=120 interval=108`, with an aggressive
mode at 10 s (`mdg_control_connection.lua`).

## 5. Routed streams

After a `place_call_reply`, the caller connects to the `routing_info.router`
endpoint and opens the routing layer (`mdg_routing_pb`):

```proto
message Handshake {
  required fixed32 magic = 1;
  required uint32 version_major = 2;
  required uint32 version_minor = 3;
  required bytes token = 4;                 // from routing_info
  repeated string supported_protocols = 5;
}
message GoAhead      { optional string selected_protocol = 1; }
message RoutingError { required RoutingErrorTypes error = 1; }
```

The callee resolves the caller by certificate: `mdg_peer_comm.verify_caller_id`
compares the peer certificate's computed id against the pairing database, then
dispatches to the handler registered for the selected protocol
(`mdg_peer_comm.register_protocol_handler`). The CC registers `cc_json`
(`cc_json.lua`, enabled from `cc_main.lua`).

LAN path: the same protocols are reachable directly on **TCP 14641**
(`mdg_lan_comm.lua`, `default_port = 14641`) — TLS with the same certificates,
then `send_lan_comm_client_handshake` / `expect_server_handshake`, then the
protocol stream. The CC enables it (`cc_main.lua`: `enable_lan_comm = true`,
`enable_mdns = true`), which makes fully local control possible when the CC is
reachable on the network.

## 6. Pairing (PACE)

Interactive, authenticated by a 5-digit OTP the CC displays.
`pairing_procedure.generate_otp` is `lbn.random(32) % 100000` formatted `%05d`.

Rendezvous (`mdg_comm_strategy.lua`): the `thing` asks the grid for a pairing
channel (`allocate_pairing_channel` → `pair_id`), communicates the OTP out of
band (its screen), and waits; the `controller` calls `place_pairing_call` with
that `pair_id`.

Framing (`mdg_pairing_protocol.lua`): magic `0xF09D8CA7` (`4036856999`), message
types `MT_CONTACT_INFO`, `MT_PACE_CLIENT_HELLO`, `MT_PACE_SERVER_HELLO`,
`MT_PACE_PK`, `MT_PACE_XY`, `MT_PACE_PROOF`:

```proto
message pace_client_hello { required fixed32 magic = 1; required uint32 version_major = 2;
                            required uint32 version_minor = 3; }
message pace_server_hello { required uint32 version_major = 1; required uint32 version_minor = 2;
                            required bytes salt = 3; required bytes iv = 4; required bytes z = 5; }
message pace_pk           { required bytes pk = 1; }
message pace_xy           { required bytes xy = 1; }
message pace_proof        { required bytes token = 1; }
message contact_info      { optional string name = 1; }
```

The shared secret is **not** just the OTP. `pairing_procedure` builds a list and
`pace.calculate_pi` length-prefixes each element with `struct.pack(">H", #v)`:

```
controller: { password, peer_public_key, own_public_key }
thing:      { otp,      own_public_key,  peer_public_key }
```

where the public keys come from the TLS certificates of the two ends
(`get_own_pubkey` reads `ssl_params.certificate`, `get_peer_pubkey` reads the
peer certificate off the socket). Binding the keys into `pi` is what makes the
OTP exchange resistant to a man in the middle at the grid.

Primitives (`pace.lua`), all on brainpoolP320r1:

| Step | Operation |
|---|---|
| `Kpi` | `crypto.pbkdf2(pi, salt, 1024, "sha256", 32)`, truncated to 16 bytes |
| nonce | `crypto.decrypt("aes-256-cbc", z, Kpi, iv, false)` → scalar via `lbn.text` |
| mapping / DH | `curve:mul(...)`, `curve:add/sub`, `random_scalar` from `ec.lua` |
| session key | `crypto.digest("sha256", curve:point2text(K), "", false)` |
| proof | `crypto.hmac.digest("sha256", curve:point2text(P), key)` |
| padding | `dbg_padding_pi = 64` |

The controller side additionally splits the entered string: the last
`dbg_padding_pi`-related characters are the OTP and the rest is treated as a
password prefix (`run_client_part`), returning `invalid password` when too
short.

On success `post_trust_steps` exchanges `contact_info` and both sides store a
pairing record (peer id, certificate, name) via `mdg_pairing_db.add_pairing`.

`peer/selftest_pace.lua` runs the vendor's own `client_part` and `server_part`
against each other through an in-process channel; they agree, which validates
the reimplemented `lbn`/`ecgroup`/`crypto` modules against the vendor Lua.

## 7. Peer operation interface

`mdg.interface` is a plain table of operations with parameter specs, timeouts
and roles; `mdg_api_util.perform_operation` validates and runs each in its own
coproc process, and `mdg_http_interface` serves them as JSON over HTTP
(`http_interface_port`, `0.0.0.0`, `Server: MDG/Xavante`).

| Operation | Input | Roles |
|---|---|---|
| `whoami` | – | all |
| `status` | – | all |
| `connect` / `disconnect` | – | all |
| `ping`, `aggressive-ping` | `duration` | all |
| `pairings` | – | all |
| `pair-remote` | `otp` | controller |
| `pair-local` | `ip`, `otp` | controller |
| `place-call` | `device_id`, `protocol`, `ticket?`, `comm_channel` | controller |
| `place-call-local` | `ip`, `device_id`, `protocol`, `ticket?`, `comm_channel` | controller |
| `revoke-pairing`, `revoke-all-pairings` | `device_id` / – | all |
| `enable-pairing-mode` | `mode` ∈ {off, local, remote}, `duration` | thing |
| `open-for-calls` | `protocol`, `channel_type`, `show_caller?` | thing |
| `prepare-3rdparty-access` | `pairing_timeout`, `access_expiry` | thing |
| `enable-remote-logging` | `duration?` | all |

`comm_channel` is a multiplexer channel number: in the app, `place-call` hands
the routed stream to the Lua↔Java multiplexer (`mdg_multiplexer.lua`, pipe fds
from `LuaVM.init0`). This project bypasses the multiplexer and calls
`mdg_control_connection.place_call` directly, so the stream stays in Lua.

Added by this project (`peer/shim/dlre_ccapi.lua`):

| Operation | Input |
|---|---|
| `cc-request` | `method`, `uri`, `content?`, `device_id?` |
| `cc-pause` | `state` ∈ {Active, Inactive}, `device_id?` |

## 8. `cc_json` and the CC REST API

On protocol `cc_json`, each 2-byte framed message is JSON that tunnels an HTTP
request to the CC's internal web server (`cc_json.lua` proxies to
`cc_json_dest_host = 127.0.0.1`; `http_interface_port = 20557` on the CC).
Request shape from `S/i.java`, response shape from `cc_json.lua`:

```json
{"id": 421590733,
 "data": {"type": "JsonWebRequest",
          "data": {"method": "PUT",
                   "uri": "/api/modes/pause",
                   "headers": ["Accept: application/json; charset=utf-8",
                               "Content-Type: application/json; charset=utf-8"],
                   "content": {"type": "Pause", "state": "Active"}}}}
```

```json
{"id": 421590733, "cc_time": 1760000000,
 "data": {"type": "JsonWebResponse", "data": { /* endpoint payload */ }}}
```

Endpoints the app uses (`com/danfoss/cumulus/comm/req/*`):

| URI | Methods | Purpose |
|---|---|---|
| `/api/modes`, `/api/modes/{mode}` | GET, PUT | house modes |
| `/api/rooms`, `/api/rooms/{id}` | GET, PATCH | per-room state and setpoints |
| `/api/onoffdevices`, `/api/onoffdevices/{id}` | GET, PATCH | switch outputs |
| `/api/settings/temperature` | GET, PATCH | temperature settings |
| `/api/system/status` | GET | system status |
| `/api/system/info` | GET, PATCH | controller info |
| `/api/system/apiversions` | GET | API versions |
| `/api/system/notify` | POST | long-poll change notification (`timeout`, `eventSyncUTC`, `eventTypes:["All"]`) |
| `/api/alarms`, `/api/alarms/{id}` | GET, PATCH | alarms |
| `/api/zones/living` | – | living zone |
| `/api/notification/register` | PUT | push registration |
| `/api/upgrade/software` | POST | firmware upgrade |

House modes (`X/n.java`, `PutModesRequest`): `AtHome`, `Vacation`, `Pause`,
`Boost`, each with `state` `Active` or `Inactive` (`X/i.java`), optional
`startTime` / `endTime`, and `rooms` (int array) for `AtHome`+`Active`. The URI
segment is the lowercase mode name: `athome`, `vacation`, `pause`, `boost`.

**Pausing heating** is therefore:

```
PUT /api/modes/pause   {"type":"Pause","state":"Active"}     # pause
PUT /api/modes/pause   {"type":"Pause","state":"Inactive"}   # resume schedule
GET /api/modes                                               # read current modes
```

## 9. Lua bytecode format 204

The `.luac` files report format `204` in the header, which stock Lua refuses.
The layout is otherwise standard Lua 5.1:

| Offset | Field | Vendor value |
|---|---|---|
| 0–3 | signature | `1B 4C 75 61` |
| 4 | version | `0x51` |
| 5 | **format** | `0xCC` (204) — stock is 0 |
| 6 | endianness | 1 (little) |
| 7 | sizeof(int) | 4 |
| 8 | sizeof(size_t) | 4 (nominal; see below) |
| 9 | sizeof(Instruction) | 4 |
| 10 | sizeof(lua_Number) | 8 |
| 11 | integral flag | 0 |

The difference: **every int and size_t in the chunk body is a big-endian 7-bit
varint** (continuation bit `0x80`), and debug info is stripped. Instructions and
numbers keep fixed width. Values below 128 encode identically to ULEB128, which
is why small files decode under either reading — the giveaway is `sizecode`.

`tools/luac204.py` rewrites such chunks into standard ones: fixed-width fields,
host `sizeof(size_t)` (8 on 64-bit, else `DLRE_SIZE_T=4`), and an injected
`@<module>.lua` source name so tracebacks identify the module despite the
missing line table. `android_main.lua` ships as both source and bytecode in the
APK, which is what made the format verifiable rather than guessed.

## 10. Native module ABI

`libluavm-java.so` is Lua 5.1.4 with statically linked OpenSSL 1.0.2s and these
`luaopen_*` entry points: `socket_core`, `mime_core`, `ssl_core`, `ssl_context`,
`ssl_x509`, `pb`, `struct`, `crypto`, `cryptomisc`, `ecgroup`, `ecpoint`, `lbn`,
`fileops`, `osmisc`, `unzip`, `zloader`. The Lua-visible `ssl.lua` is verbatim
LuaSec 0.5, and the protobuf runtime is protoc-gen-lua.

What the pairing path needs, and how this project supplies it
(`work/dlrenative.c`, OpenSSL BN/EC/EVP):

| Module | Members used by vendor Lua |
|---|---|
| `lbn` | `number` (accepts `"x<hex>"`), `text`, `totext`, `random`, `tonumber`, `bits`, `__mod`/`__lt`/`__add`/… |
| `ecgroup` | `new_GFp(p,a,b,Gx,Gy,order,cofactor)`; methods `degree`, `order`, `generator`, `mul`, `add`, `sub`, `is_on_curve`, `is_at_infinity`, `point2text`, `text2point` |
| `ecpoint` | point objects (methods live on the group) |
| `crypto` | `digest(alg,data,key,raw)`, `hmac.digest(alg,data,key,raw)`, `pbkdf2(pass,salt,iter,alg,len)`, `encrypt`/`decrypt(alg,data,key,iv,pad)`, `rand.bytes` |
| `cryptomisc` | reached under both names; same table |

One vendor idiom matters: the module table **is** the metatable `__index`, so
`ec.lua` can do `require("ecgroup").random_scalar = …` and `curve:random_scalar()`
then resolves. A namespaced module breaks the stack.

Compatibility gaps against current rocks, patched in `peer/shim/mdgcompat.lua`:

| Gap | Fix |
|---|---|
| `ssl.x509` field absent; no `cert:subject_key_identifier()` | expose `ssl.x509`, add the method (SKI extension, else SHA-1 of the SPKI BIT STRING) |
| `ssl_params.cipher` (LuaSec 0.5) | mapped to `ciphers` |
| `ssl_params.curve` fails for brainpool | mapped to `curveslist` (`SSL_CTX_set1_curves_list`), with fallback |
| `socket.tcp()` allocates the fd lazily in LuaSocket 3.x, so `setoption("reuseaddr")` before `bind` fails | `socket.tcp = socket.tcp4` |
| LPeg ≥ 1.0 exposes `version` as a string | wrapped back into a function |
| `fileops.listdir` is an iterator, not a table | `peer/shim/fileops.lua` |
| `osmisc.hires_time` and friends | `peer/shim/osmisc.lua` |
