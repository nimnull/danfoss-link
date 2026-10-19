-- Trust anchor for the MDG grid, replacing OpenSSL chain verification.
--
-- Every Trifork certificate (grid CA, grid servers, and the CC itself) carries
-- an EC public key with *explicit* curve parameters. OpenSSL 1.0.2 -- which the
-- vendor stack shipped -- accepts those; OpenSSL 3 fails verification with
-- X509_V_ERR_EC_KEY_EXPLICIT_PARAMS (94) and no flag turns that off.
--
-- So the handshake runs with LuaSec's "lsec_continue" (verification errors are
-- not fatal) and trust is established here instead: the presented chain must
-- contain the exact CA certificate bundled in the Danfoss app
-- (luafiles/trusted-CAs.pem). That is certificate pinning, which for a fixed
-- service is at least as strong as CA path validation.
local M = {}

local pinned = {}       -- normalised base64 body -> true
local pinned_count = 0

local function normalise(pem)
  if type(pem) ~= "string" then return nil end
  local body = pem:gsub("%-%-%-%-%-[^%-]+%-%-%-%-%-", ""):gsub("%s", "")
  if body == "" then return nil end
  return body
end

function M.load_ca_file(path)
  local fh = io.open(path, "rb")
  if not fh then return nil, "cannot read " .. tostring(path) end
  local text = fh:read("*a")
  fh:close()
  for block in text:gmatch("%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-.-%-%-%-%-%-END CERTIFICATE%-%-%-%-%-") do
    local body = normalise(block)
    if body and not pinned[body] then
      pinned[body] = true
      pinned_count = pinned_count + 1
    end
  end
  return pinned_count
end

function M.count()
  return pinned_count
end

-- Returns true when the peer presented a chain containing a pinned cert.
function M.check(sock)
  if pinned_count == 0 then return nil, "no pinned CA loaded" end

  local certs = {}
  if sock.getpeerchain then
    local ok, chain = pcall(sock.getpeerchain, sock)
    if ok and type(chain) == "table" then
      for _, cert in ipairs(chain) do table.insert(certs, cert) end
    end
  end
  if sock.getpeercertificate then
    local ok, leaf = pcall(sock.getpeercertificate, sock)
    if ok and leaf then table.insert(certs, leaf) end
  end
  if #certs == 0 then return nil, "peer presented no certificate" end

  for _, cert in ipairs(certs) do
    local ok, pem = pcall(cert.pem, cert)
    if ok then
      local body = normalise(pem)
      if body and pinned[body] then return true end
    end
  end
  return nil, "peer chain does not contain the pinned MDG CA"
end

return M
