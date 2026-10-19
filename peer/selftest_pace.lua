-- Runs the vendor PACE client and server halves against each other through an
-- in-process channel. Exercises lbn / ecgroup / crypto end to end.
package.path = "/peer/shim/?.lua;/peer/lua/?.lua;" .. package.path
fileops = require("fileops")
osmisc = require("osmisc")

local ec = require("ec")
local curve = ec.create_curve(ec.brainpoolp320r1)
print("curve degree:", curve:degree())
print("order bits:", require("lbn").bits(curve:order()))
local G = curve:generator()
print("generator on curve:", curve:is_on_curve(G), "at infinity:", curve:is_at_infinity(G))
local k = require("ecgroup").random_scalar(curve)
local P = curve:mul(G, k)
print("k*G on curve:", curve:is_on_curve(P))
local oct = curve:point2text(P)
print("point2text bytes:", #oct, "roundtrip:", curve:is_on_curve(curve:text2point(oct)))

local crypto = require("crypto")
print("sha256(abc):", crypto.digest("sha256", "abc", "", false):sub(1, 16) .. "...")
print("pbkdf2 len:", #crypto.pbkdf2("pw", "salt", 1024, "sha256", 32))
local ct = crypto.encrypt("aes-256-cbc", ("A"):rep(32), ("k"):rep(32), ("i"):rep(16), false)
local pt = crypto.decrypt("aes-256-cbc", ct, ("k"):rep(32), ("i"):rep(16), false)
print("aes roundtrip:", pt == ("A"):rep(32))

local pace = require("pace")
-- pairing_procedure builds the PACE secret as
--   { password, peer_public_key_pem, own_public_key_pem }
-- and calculate_pi() length-prefixes each element.
local secret = { "12345", "peer-public-key-pem", "own-public-key-pem" }
local to_server, to_client = {}, {}
local client_co, server_co

local function channel(outbox, inbox)
  return function(op, msg)
    if op == "send" then
      table.insert(outbox, msg)
      coroutine.yield()
      return true
    elseif op == "receive" then
      while #inbox == 0 do coroutine.yield() end
      return table.remove(inbox, 1)
    end
    error("unknown channel op " .. tostring(op))
  end
end

client_co = coroutine.create(function()
  return pace.client_part(secret, channel(to_server, to_client))
end)
server_co = coroutine.create(function()
  return pace.server_part(secret, channel(to_client, to_server))
end)

local cres, sres
for _ = 1, 40 do
  if coroutine.status(client_co) == "suspended" then
    local ok, r = coroutine.resume(client_co)
    if not ok then print("client error:", r); break end
    if coroutine.status(client_co) == "dead" then cres = r end
  end
  if coroutine.status(server_co) == "suspended" then
    local ok, r = coroutine.resume(server_co)
    if not ok then print("server error:", r); break end
    if coroutine.status(server_co) == "dead" then sres = r end
  end
  if cres ~= nil and sres ~= nil then break end
end
print("client result:", type(cres), tostring(cres):sub(1, 40))
print("server result:", type(sres), tostring(sres):sub(1, 40))
if type(cres) == "string" and type(sres) == "string" then
  print("PACE agreement:", cres == sres)
end
