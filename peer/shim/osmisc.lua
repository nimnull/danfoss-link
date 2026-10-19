-- Replacement for Trifork's native `osmisc` module (Lua 5.1).
-- Unknown members are reported on stderr and stubbed.
local socket = require("socket")
-- luaposix pulls in the `std` stack and is not worth the noise here
local ok_posix, posix = false, nil

local M = {}

function M.hostname()
  if ok_posix and posix.uname then
    local u = posix.uname("%n")
    if u then return u end
  end
  local fh = io.popen("hostname 2>/dev/null")
  if fh then
    local h = (fh:read("*l") or "localhost")
    fh:close()
    return h
  end
  return "localhost"
end

function M.getpid()
  if ok_posix and posix.getpid then
    local p = posix.getpid()
    return type(p) == "table" and p.pid or p
  end
  return 0
end

function M.gettime()
  return socket.gettime()
end

M.time = M.gettime
M.hires_time = M.gettime
M.monotime = M.gettime

function M.monotonic_time()
  return socket.gettime()
end

function M.sleep(seconds)
  return socket.sleep(seconds or 0)
end

function M.meminfo()
  return { rss = 0, vsize = 0 }
end

function M.memory_usage()
  return collectgarbage("count") * 1024
end

-- mDNS needs the local interface addresses.
function M.interfaces()
  local out = {}
  local fh = io.popen("ip -4 -o addr show 2>/dev/null || ifconfig 2>/dev/null")
  if fh then
    local text = fh:read("*a") or ""
    fh:close()
    for ip in text:gmatch("inet%s+(%d+%.%d+%.%d+%.%d+)") do
      if ip ~= "127.0.0.1" then table.insert(out, ip) end
    end
    for ip in text:gmatch("inet%s(%d+%.%d+%.%d+%.%d+)/%d+") do
      if ip ~= "127.0.0.1" then table.insert(out, ip) end
    end
  end
  if #out == 0 then table.insert(out, "127.0.0.1") end
  return out
end

M.local_addresses = M.interfaces
M.ip_addresses = M.interfaces

function M.random_bytes(n)
  local fh = io.open("/dev/urandom", "rb")
  if fh then
    local b = fh:read(n or 16)
    fh:close()
    if b then return b end
  end
  local t = {}
  for _ = 1, (n or 16) do table.insert(t, string.char(math.random(0, 255))) end
  return table.concat(t)
end

function M.setenv(k, v)
  if ok_posix and posix.setenv then return posix.setenv(k, v) end
  return nil, "setenv unavailable"
end

return setmetatable(M, {
  __index = function(_, key)
    io.stderr:write("[shim] osmisc." .. tostring(key) .. " requested (stubbed)\n")
    return function() return nil, "osmisc." .. tostring(key) .. " not implemented" end
  end,
})
