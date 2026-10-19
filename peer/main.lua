-- Linux bootstrap for the vendor MDG peer stack (replaces Trifork's native
-- `lush` bootstrap: android_main.lua / cc_main.lua / windows_sandbox_main.lua).
io.stdout:setvbuf("line")
io.stderr:setvbuf("line")

-- The vendor process framework swallows tracebacks via pcall; keep the last
-- one so the log sink can print where a coproc actually died.
local real_pcall = pcall
LAST_TRACEBACK = nil
function pcall(f, ...)
  local n = select("#", ...)
  local args = { ... }
  return xpcall(function()
    return f(unpack(args, 1, n))
  end, function(err)
    local msg = tostring(err)
    if not msg:match("module '[^']+' not found") then
      LAST_TRACEBACK = debug.traceback(msg, 2)
    end
    return err
  end)
end

local DATA = os.getenv("MDG_DATADIR") or "/peer/data"
local RES = os.getenv("MDG_RESOURCEDIR") or "/peer/lua"

LUSH_DATA_DIR = DATA
LUSH_RESOURCE_DIR = RES
DATADIR, INFODIR, CONFIGDIR = DATA, DATA, DATA

-- the native bootstrap exposes these as globals
fileops = require("fileops")
osmisc = require("osmisc")
require("mdgcompat")   -- LuaSec 1.x <-> vendor LuaSec 0.5 gap
fileops.makedir(DATA)

local attach_log_sinks

-- Read once; used for the data dir and the opt-in debug flag.
local function flag(name)
  local fh = io.open(DATA .. "/" .. name, "rb")
  if not fh then return nil end
  local v = fh:read("*a")
  fh:close()
  return (v or ""):gsub("%s", ""):lower()
end

local function init(config)
  config.name = os.getenv("MDG_NAME") or "dlre-bridge"
  -- Connect to the grid at startup instead of waiting for a /connect call.
  -- Pairings already survive a container restart (they live in MDG_DATADIR),
  -- but the grid connection did not: a restarted container came back with
  -- connect_switch=false and every request failed with "not connected to the
  -- grid" until something poked /connect. With this the peer is usable as soon
  -- as the container is up, which is what `restart: unless-stopped` implies.
  config.auto_connect = true
  config.mdg_control_dnsname = "mdg-danfoss.hosted.trifork.com"
  config.mdg_control_min_wait = 5
  config.mdg_control_max_wait = 30

  -- The vendor stack prefers two hardcoded control-server sets
  -- (77.66.11.90/.92 and 5.179.92.180/.182) over DNS, while
  -- mdg-danfoss.hosted.trifork.com resolves to more addresses. A comma-separated
  -- IP list in <MDG_DATADIR>/grid_hosts overrides both and pins the control
  -- connection to those servers; absent, the vendor default selection is used.
  local hosts = flag("grid_hosts")
  if hosts and hosts ~= "" then
    local set = {}
    for ip in hosts:gmatch("[^,]+") do
      set[#set + 1] = { ip, 443 }
    end
    if #set > 0 then
      config.mdg_control_hosts_hardcoded_ip_sets = { set }
      config.mdg_control_hosts_hardcoded_ips = nil
      print("[main] grid hosts pinned to " .. hosts)
    end
  end

  config.ssl_params.protocol = "tlsv1_2"
  config.ssl_params.key = DATA .. "/app_key.pem"
  config.ssl_params.certificate = DATA .. "/app_cert.pem"
  config.ssl_params.cafile = RES .. "/trusted-CAs.pem"
  config.ssl_params.verify = { "peer" }
  config.ssl_params.options = { "all" }
  config.want_selfsigned_cert = false

  config.http_interface_port = tonumber(os.getenv("MDG_HTTP_PORT") or "20558")
  -- Op roles in mdg.lua are "*all" / "thing" / "controller"; "*all" is a role
  -- name ops can carry, not a wildcard grant. pair-remote is controller-only,
  -- so the role list has to name it explicitly.
  config.http_interface_roles = { "*all", "controller", "thing" }
  config.max_routing_connections = 5
  config.enable_lan_comm = os.getenv("MDG_LAN") ~= "0"
  config.enable_mdns = os.getenv("MDG_MDNS") == "1"
  config.file_logging = false
  attach_log_sinks("init")
end

-- Route the vendor logger to stdout; mdg_logging only wires file/remote sinks.
-- Called from both init and post_init because either can be the first hook to
-- run, but the sinks must be installed only once: adding them twice printed
-- every log line twice.
local sinks_attached = false

function attach_log_sinks(tag)
  if sinks_attached then return end
  sinks_attached = true
  local logger = require("logger")
  for _, level in ipairs({ "debug", "info", "warn", "error" }) do
    logger.add_level_sink(level, function(...)
      local parts = {}
      for i = 1, select("#", ...) do
        local v = select(i, ...)
        if type(v) == "table" then
          local ok, dump = pcall(function()
            local acc = {}
            for k, vv in pairs(v) do acc[#acc + 1] = tostring(k) .. "=" .. tostring(vv) end
            return "{" .. table.concat(acc, ", ") .. "}"
          end)
          parts[#parts + 1] = ok and dump or tostring(v)
        else
          parts[#parts + 1] = tostring(v)
        end
      end
      print("[" .. level .. "] " .. table.concat(parts, " | "))
      if level == "error" and LAST_TRACEBACK then
        print(LAST_TRACEBACK)
        LAST_TRACEBACK = nil
      end
    end)
  end
  print("[main] log sinks attached (" .. tag .. ")")
end

local function post_init()
  attach_log_sinks("post_init")
  -- Danfoss CC REST-over-MDG, exposed as /cc-request and /cc-pause
  local ok, err = pcall(function() require("dlre_ccapi").register() end)
  if not ok then print("[main] dlre_ccapi failed: " .. tostring(err)) end

  print("[main] post_init hook done; http interface should be up")
end

-- the native bootstrap also prefills an empty ssl_params table
local common = require("common_peer_config")
common.boot(function(config)
  config.ssl_params = config.ssl_params or {}
  return init(config)
end, post_init)
