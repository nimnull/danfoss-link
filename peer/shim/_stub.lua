-- Placeholder for Trifork's native crypto modules (lbn, ecgroup, ecpoint, ec,
-- crypto, cryptomisc). Those are only needed for PACE pairing and for
-- generating a self-signed identity; the grid/tunnel path does not use them.
--
-- The vendor modules build curve objects at load time, so a stub must survive
-- being called and indexed. Any *arithmetic* use raises, so silent wrong
-- results are impossible.
local function fail(what)
  error(what .. ": native crypto module not implemented in this port "
        .. "(pairing-only code path)", 3)
end

local function lazy(path)
  local obj
  obj = setmetatable({}, {
    __index = function(_, key)
      if type(key) ~= "string" then return nil end
      return function() return lazy(path .. "." .. tostring(key)) end
    end,
    __call = function() return lazy(path .. "()") end,
    __add = function() fail(path .. " +") end,
    __sub = function() fail(path .. " -") end,
    __mul = function() fail(path .. " *") end,
    __div = function() fail(path .. " /") end,
    __mod = function() fail(path .. " %") end,
    __pow = function() fail(path .. " ^") end,
    __eq = function() fail(path .. " ==") end,
    __lt = function() fail(path .. " <") end,
    __concat = function() return path end,
    __tostring = function() return "<stub " .. path .. ">" end,
    __len = function() fail(path .. " #") end,
  })
  return obj
end

return function(name)
  return lazy(name)
end
