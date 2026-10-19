-- Danfoss CC application protocol, exposed as extra MDG operations.
--
-- The Link app reaches the CC's REST API by opening an MDG call with protocol
-- "cc_json" and exchanging length-prefixed JSON frames (see cc_json.lua on the
-- CC side and S/i.java in the app):
--
--   request  {"id":N,"data":{"type":"JsonWebRequest",
--                            "data":{"method":..,"uri":..,"headers":[..],"content":{..}}}}
--   response {"id":N,"cc_time":T,"data":{"type":"JsonWebResponse","data":<payload>}}
--
-- Registering into mdg.interface means these are served by the peer's existing
-- HTTP interface with parameter checking, timeouts and role handling:
--
--   GET /cc-request?method=GET&uri=/api/modes
--   GET /cc-request?method=PUT&uri=/api/modes/pause&content={"type":"Pause","state":"Active"}
local mdg = require("mdg")
local control_connection = require("mdg_control_connection")
local pairing_db = require("mdg_pairing_db")
local coproc = require("coproc")
local cotcp = require("cotcp")
local json = require("dkjson")
local log = require("logger").init("dlre_ccapi")

local M = {}

local next_id = 0
local function request_id()
  next_id = (next_id + 1) % 0x7fffffff
  return next_id
end

-- A pairing record holds peer_id, certificate, name, metadata and pairing_time
-- (no ticket -- place_call takes "" for that). list_pairings() returns an array,
-- not a map keyed by peer id, so iterating with pairs() yields integer keys;
-- passing one of those to place_call produced
--   place_call | 1 | cc_json
--   coproc died with "1 has type number, but expected one of: string"
-- which also tore down the control connection. Take the id from the record and
-- accept either shape.
local function record_id(key, rec)
  if type(rec) == "table" then
    local id = rec.peer_id or rec.device_id or rec.id
    if type(id) == "string" and id ~= "" then return id end
  end
  if type(key) == "string" and key ~= "" then return key end
  return nil
end

local function record_ticket(rec)
  if type(rec) ~= "table" then return nil end
  return rec.ticket or rec.pairing_ticket
end

-- The grid routes by peer_name in colon-separated hex (f7:6e:...); pairing
-- records store plain 40-char hex. Convert so place_call matches the grid.
local function to_peer_name(id)
  if type(id) == "string" and #id == 40 and id:match("^%x+$") then
    return (id:gsub("..", "%0:"):gsub(":$", ""))
  end
  return id
end

local function resolve_peer(device_id)
  local pairings = pairing_db.list_pairings() or {}
  if device_id and device_id ~= "" then
    for key, rec in pairs(pairings) do
      if record_id(key, rec) == device_id then
        return device_id, record_ticket(rec)
      end
    end
    -- Not in the list; let the grid decide whether the id is usable.
    return device_id, nil
  end
  local found_id, found_rec, count = nil, nil, 0
  for key, rec in pairs(pairings) do
    local id = record_id(key, rec)
    if id then
      count = count + 1
      found_id, found_rec = id, rec
    end
  end
  if count == 0 then return nil, nil, "no pairings: pair with the CC first" end
  if count > 1 then return nil, nil, "several pairings, pass device_id" end
  return found_id, record_ticket(found_rec)
end

function M.cc_json_exchange(device_id, payload, timeout)
  local control = coproc.whereis("process", "mdg_control")
  if not control then return nil, "not connected to the grid" end

  local peer_id, ticket, err = resolve_peer(device_id)
  if not peer_id then return nil, err end

  local sock, perr = control_connection.place_call(control, to_peer_name(peer_id), "cc_json", ticket or "")
  if not sock then return nil, "place_call failed: " .. tostring(perr) end

  cotcp.setopt(sock, { packet = 2 })

  local ok, serr = cotcp.send(sock, payload, timeout)
  if not ok then
    pcall(cotcp.close, sock)
    return nil, "send failed: " .. tostring(serr)
  end

  local reply, rerr = cotcp.recv(sock, timeout)
  pcall(cotcp.close, sock)
  if not reply then return nil, "receive failed: " .. tostring(rerr) end
  return reply
end

-- method/uri/content -> decoded JsonWebResponse payload
function M.cc_request(device_id, method, uri, content, timeout)
  timeout = timeout or 15
  local body = {
    id = request_id(),
    data = {
      type = "JsonWebRequest",
      data = {
        method = method,
        uri = uri,
        headers = { "Accept: application/json; charset=utf-8" },
      },
    },
  }
  if content ~= nil and content ~= "" then
    local decoded, _, derr = json.decode(content)
    if derr then return nil, "content is not JSON: " .. tostring(derr) end
    body.data.data.content = decoded
    table.insert(body.data.data.headers, "Content-Type: application/json; charset=utf-8")
  end

  local raw, err = M.cc_json_exchange(device_id, json.encode(body), timeout)
  if not raw then return nil, err end

  local decoded, _, derr = json.decode(raw)
  if derr then return nil, "cannot decode CC reply: " .. tostring(derr) end
  if type(decoded) ~= "table" or type(decoded.data) ~= "table" then
    return nil, "unexpected CC reply shape"
  end
  return {
    id = decoded.id,
    cc_time = decoded.cc_time,
    type = decoded.data.type,
    payload = decoded.data.data,
  }
end

-- House modes are what pause/resume heating: PUT /api/modes/pause
--   {"type":"Pause","state":"Active"}   -> heating paused
--   {"type":"Pause","state":"Inactive"} -> back to schedule
function M.set_pause(device_id, active)
  local state = active and "Active" or "Inactive"
  return M.cc_request(device_id, "PUT", "/api/modes/pause",
                      json.encode({ type = "Pause", state = state }))
end

function M.register()
  mdg.interface["cc-request"] = {
    input = {
      { "method", "string" },
      { "uri", "string" },
      { "content", { "optional", "string" } },
      { "device_id", { "optional", "string" } },
    },
    timeout = 25,
    roles = "*all",
    action = function(method, uri, content, device_id)
      local result, err = M.cc_request(device_id, method, uri, content)
      if not result then return { result = "failed", error_text = tostring(err) } end
      result.result = "ok"
      return result
    end,
  }

  mdg.interface["cc-pause"] = {
    input = {
      { "state", { "in_set", { Active = true, Inactive = true } } },
      { "device_id", { "optional", "string" } },
    },
    timeout = 25,
    roles = "*all",
    action = function(state, device_id)
      local result, err = M.set_pause(device_id, state == "Active")
      if not result then return { result = "failed", error_text = tostring(err) } end
      result.result = "ok"
      return result
    end,
  }

  log("info", "dlre_ccapi: registered cc-request and cc-pause operations")
  return M
end

return M
