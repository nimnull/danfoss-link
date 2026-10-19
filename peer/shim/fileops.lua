-- Replacement for Trifork's native `fileops` module (Lua 5.1).
-- Unknown members are reported on stderr and stubbed, so the exact API
-- surface the vendor stack needs becomes visible while booting.
local lfs = require("lfs")

local M = {}

function M.makedir(path)
  if not path or path == "" then return nil, "no path" end
  local acc = (path:sub(1, 1) == "/") and "/" or ""
  for part in path:gmatch("[^/\\]+") do
    acc = (acc == "" or acc == "/") and (acc .. part) or (acc .. "/" .. part)
    local attr = lfs.attributes(acc)
    if not attr then
      local ok, err = lfs.mkdir(acc)
      if not ok and not lfs.attributes(acc) then return nil, err end
    elseif attr.mode ~= "directory" then
      return nil, acc .. " exists and is not a directory"
    end
  end
  return true
end

function M.exists(path)
  return lfs.attributes(path) ~= nil
end

function M.isdir(path)
  local a = lfs.attributes(path)
  return a ~= nil and a.mode == "directory"
end

function M.filesize(path)
  local a = lfs.attributes(path)
  return a and a.size or nil
end

M.size = M.filesize

function M.mtime(path)
  local a = lfs.attributes(path)
  return a and a.modification or nil
end

function M.remove(path)
  return os.remove(path)
end

M.delete = M.remove
M.unlink = M.remove

function M.rename(from, to)
  return os.rename(from, to)
end

function M.readfile(path)
  local fh = io.open(path, "rb")
  if not fh then return nil, "cannot open " .. tostring(path) end
  local data = fh:read("*a")
  fh:close()
  return data
end

function M.writefile(path, data)
  local fh = io.open(path, "wb")
  if not fh then return nil, "cannot write " .. tostring(path) end
  fh:write(data or "")
  fh:close()
  return true
end

function M.listdir_table(path)
  local out = {}
  local ok = pcall(function()
    for name in lfs.dir(path) do
      if name ~= "." and name ~= ".." then table.insert(out, name) end
    end
  end)
  if not ok then return {} end
  return out
end

-- The vendor module hands back an iterator: `for name in fileops.listdir(d) do`
function M.listdir(path)
  local names = M.listdir_table(path)
  local i = 0
  return function()
    i = i + 1
    return names[i]
  end
end

M.dir = M.listdir
M.files = M.listdir
M.entries = M.listdir

function M.freespace()
  return 1024 * 1024 * 1024
end

-- DLRE_TRACE=1 logs every fileops call: the vendor stack's expectations about
-- this native module are not documented anywhere.
if os.getenv("DLRE_TRACE") == "1" then
  for name, fn in pairs(M) do
    if type(fn) == "function" then
      M[name] = function(...)
        local args = {}
        for i = 1, select("#", ...) do args[#args + 1] = tostring(select(i, ...)) end
        io.stderr:write("[trace] fileops." .. name .. "(" .. table.concat(args, ", ") .. ")\n")
        return fn(...)
      end
    end
  end
end

return setmetatable(M, {
  __index = function(_, key)
    io.stderr:write("[shim] fileops." .. tostring(key) .. " requested (stubbed)\n")
    return function() return nil, "fileops." .. tostring(key) .. " not implemented" end
  end,
})
