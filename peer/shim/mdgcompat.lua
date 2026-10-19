-- Compatibility patches between stock LuaSec (1.3.x) and Trifork's patched
-- LuaSec 0.5: the vendor stack calls `ssl.x509.load(pem):subject_key_identifier()`
-- to derive peer ids (MDG peer_name == certificate Subject Key Identifier).
local ssl = require("ssl")
local x509 = require("ssl.x509")

ssl.x509 = ssl.x509 or x509

-- LPeg >= 1.0 turned `lpeg.version` from a function into a string; the vendor
-- `pattern` module still calls it.
do
  local ok, lpeg = pcall(require, "lpeg")
  if ok and type(lpeg.version) == "string" then
    local v = lpeg.version
    lpeg.version = function() return v end
  end
end

-- Trifork's patched LuaSocket exposed `sock:set_buffering()`; `cotcp.lua` calls
-- it on the routing connection, which is the path pairing uses. Upstream
-- LuaSocket has no such method, so the routing socket died with
-- "attempt to call method 'set_buffering' (a nil value)". Buffering is not
-- observable through the vendor's explicit receive patterns, so a no-op is
-- enough. LuaSocket mutates a socket's class on connect (master -> client),
-- each class having its own shared metatable, so the connect method is wrapped
-- to re-patch whatever class the object ends up in.
local function ensure_set_buffering(obj)
  local mt = getmetatable(obj)
  local index = mt and mt.__index
  if type(index) ~= "table" then return obj end
  if not index.set_buffering then
    index.set_buffering = function() return 1 end
  end
  if not index.__sb_hooked and type(index.connect) == "function" then
    index.__sb_hooked = true
    local real_connect = index.connect
    index.connect = function(self, ...)
      local ok, err = real_connect(self, ...)
      ensure_set_buffering(self)
      return ok, err
    end
  end
  return obj
end

-- LuaSocket 3.x creates the fd lazily in socket.tcp(), so the vendor's
-- `setoption("reuseaddr")` before bind() fails. tcp4() allocates eagerly.
do
  local socket = require("socket")
  if socket.tcp4 then socket.tcp = socket.tcp4 end
  local probe = socket.tcp()
  if probe then
    ensure_set_buffering(probe)
    pcall(function() probe:close() end)
  end
end

-- The vendor config uses LuaSec 0.5 spelling (`cipher`) and asks for the
-- brainpoolP320r1 ECDHE group, which OpenSSL 3 refuses to set. Peer
-- certificates stay brainpool either way; only the ephemeral group changes,
-- and the grid negotiates a standard one. ssl.wrap() builds its own context
-- internally, so both entry points need the same treatment.
local pin = require("mdgpin")

local function sanitize(params)
  if type(params) ~= "table" then return params end
  local p = {}
  for k, v in pairs(params) do p[k] = v end
  if p.cipher and not p.ciphers then p.ciphers = p.cipher end
  p.cipher = nil
  -- Device-to-device (routing) legs are rejected by mdg_routing_connection with
  -- "Peer connect failed: ssl_info.bits < 256". The vendor cipher list names the
  -- AES128 suites first and the CC honours client preference, so the leg came up
  -- as ECDHE-ECDSA-AES128-GCM-SHA256 (128 bits). Keep only the 256-bit suites on
  -- that path; the grid control connection keeps the original list.
  if p.verifyext and type(p.ciphers) == "string" then
    local strong = {}
    for suite in p.ciphers:gmatch("[^:]+") do
      if suite:find("AES256", 1, true) then strong[#strong + 1] = suite end
    end
    if #strong > 0 then p.ciphers = table.concat(strong, ":") end
  end
  -- LuaSec's `curve` is the server-side tmp-ECDH path and fails for brainpool.
  -- `curveslist` maps to SSL_CTX_set1_curves_list, which is what a client needs
  -- so the brainpool peer certificate passes tls12_check_peer_sigalg.
  if p.curve and not p.curveslist then
    p.curveslist = p.curve .. ":prime256v1:secp384r1:secp521r1"
    p.curve = nil
  end
  -- OpenSSL 1.1.1 validates this chain fine; the pin check in the dohandshake
  -- hook below is a second gate, not a replacement.
  if p.cafile then pin.load_ca_file(p.cafile) end
  return p
end

-- Patch the shared LuaSec socket metatable once an object exists: verification
-- is advisory now, so the pin check must gate every completed handshake.
-- Per-connection pin policy. The CA pin only applies to connections terminated
-- by the grid itself (control, and the relay leg before it is upgraded). A
-- *routing* connection is relayed device-to-device, so the peer certificate is
-- the CC's own device cert, signed by a CA that is deliberately not in
-- trusted-CAs.pem. There, authentication comes from PACE during pairing and
-- afterwards from the peer cert's Subject Key Identifier matching the expected
-- peer id (mdg.lua remember_peer_cert) -- not from a chain. The vendor marks
-- exactly those connections by passing verifyext="lsec_continue".
local pin_policy = setmetatable({}, { __mode = "k" })

local hooked = false
local function install_handshake_hook(obj)
  local mt = getmetatable(obj)
  local index = mt and mt.__index
  if type(index) ~= "table" or type(index.dohandshake) ~= "function" then return end
  local real_dohandshake = index.dohandshake
  index.dohandshake = function(self, ...)
    local ok, err = real_dohandshake(self, ...)
    if not ok then return ok, err end
    -- Unknown objects fail closed; only an explicit "device" marking skips.
    if pin_policy[self] == "device" then
      return ok, err
    end
    local pinned_ok, pin_err = pin.check(self)
    if not pinned_ok then
      pcall(self.close, self)
      return nil, "pin check failed: " .. tostring(pin_err)
    end
    return ok, err
  end
  hooked = true
end

-- brainpoolP320r1 must be in the TLS supported-groups list: both the grid and
-- the CC present brainpool ECDSA certs, and TLS 1.2 rejects a peer sigalg whose
-- curve was not advertised. OpenSSL 1.1.1 accepts the group; if a future
-- OpenSSL refuses, fall back so the rest of the stack still runs.
local function with_fallback(call, params)
  local p = sanitize(params)
  local obj, err = call(p)
  if obj or not p.curveslist then return obj, err end
  local without = {}
  for k, v in pairs(p) do without[k] = v end
  without.curveslist = nil
  io.stderr:write("[compat] curveslist " .. tostring(p.curveslist) .. " rejected (" ..
                  tostring(err) .. "), retrying without it\n")
  return call(without)
end

do
  local real_newcontext = ssl.newcontext
  ssl.newcontext = function(params)
    return with_fallback(function(p) return real_newcontext(p) end, params)
  end

  local real_wrap = ssl.wrap
  ssl.wrap = function(sock, params)
    local obj, err = with_fallback(function(p) return real_wrap(sock, p) end, params)
    if obj and not hooked then install_handshake_hook(obj) end
    if obj then
      ensure_set_buffering(obj)
      if type(params) == "table" and params.verifyext then
        pin_policy[obj] = "device"
      else
        pin_policy[obj] = "grid"
      end
    end
    return obj, err
  end
end

local M = {}

local function tmpname()
  return os.tmpname()
end

local function run(cmd)
  local fh = io.popen(cmd .. " 2>/dev/null")
  if not fh then return nil end
  local out = fh:read("*a")
  fh:close()
  return out
end

local function read_file(path)
  local fh = io.open(path, "rb")
  if not fh then return nil end
  local data = fh:read("*a")
  fh:close()
  return data
end

local function write_file(path, data)
  local fh = io.open(path, "wb")
  if not fh then return nil end
  fh:write(data)
  fh:close()
  return true
end

-- minimal DER walk: SubjectPublicKeyInfo ::= SEQUENCE { alg, BIT STRING }
local function spki_bitstring(der)
  local pos = 1
  local function tlv()
    local tag = der:byte(pos)
    local len = der:byte(pos + 1)
    local hdr = 2
    if len > 0x80 then
      local n = len - 0x80
      len = 0
      for i = 1, n do len = len * 256 + der:byte(pos + 1 + i) end
      hdr = 2 + n
    elseif len == 0x80 then
      return nil
    end
    local body = der:sub(pos + hdr, pos + hdr + len - 1)
    pos = pos + hdr + len
    return tag, body
  end
  local tag, seq = tlv()
  if tag ~= 0x30 or not seq then return nil end
  pos = 1
  der = seq
  while pos <= #der do
    local t, body = tlv()
    if not t then return nil end
    if t == 0x03 then
      -- strip the "unused bits" octet
      return body:sub(2)
    end
  end
  return nil
end

-- SKI, as OpenSSL computes it: SHA-1 over the public key BIT STRING.
function M.subject_key_identifier(pem)
  local cert_path = tmpname()
  write_file(cert_path, pem)

  local ext = run("openssl x509 -in " .. cert_path .. " -noout -ext subjectKeyIdentifier")
  local hex = ext and ext:match("([0-9A-Fa-f][0-9A-Fa-f](:[0-9A-Fa-f][0-9A-Fa-f])+)")
  if not hex then
    local der_path = tmpname()
    run("openssl x509 -in " .. cert_path .. " -pubkey -noout | openssl pkey -pubin -outform DER -out " .. der_path)
    local der = read_file(der_path)
    os.remove(der_path)
    local bits = der and spki_bitstring(der)
    if bits then
      local bits_path = tmpname()
      write_file(bits_path, bits)
      local dgst = run("openssl dgst -sha1 -hex " .. bits_path)
      os.remove(bits_path)
      hex = dgst and dgst:match("([0-9a-fA-F]+)%s*$")
    end
  end
  os.remove(cert_path)
  if not hex then return nil, "cannot derive subject key identifier" end
  return (hex:gsub(":", "")):lower()
end

-- Patch the certificate metatable so vendor code can call the method.
local datadir = os.getenv("MDG_DATADIR") or "/peer/data"
local probe = x509.load(read_file(datadir .. "/app_cert.pem"))
if probe then
  local mt = getmetatable(probe)
  local index = mt and mt.__index
  if index and not index.subject_key_identifier then
    index.subject_key_identifier = function(self)
      return M.subject_key_identifier(self:pem())
    end
  end

  -- No patch needed for `cert:pubkey()`. PACE hashes
  -- { password, peer_pubkey, own_pubkey } using the first return of that call,
  -- and `pairing_procedure.lua` destructures three values from it, which is
  -- exactly LuaSec's `(pem, type, bits)` contract in both 0.5 and 1.3. PEM is
  -- therefore correct; returning DER here breaks pairing. Verified by pairing
  -- successfully with PEM after an experiment with DER failed.
end

return M
