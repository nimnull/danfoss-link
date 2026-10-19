#!/usr/bin/env python3
"""MQTT bridge between Home Assistant and the Danfoss Link CC.

The MDG peer (Lua) owns the grid connection and exposes the CC's REST API over
its local HTTP operation interface. This process is the Home-Assistant-facing
half: it publishes discovery and mirrors CC state, and turns HA commands into
CC REST writes -- house pause and vacation modes, per-room setpoints, the
vacation temperature, and on/off devices.

Pausing is a house mode on the CC:
    PUT /api/modes/pause {"type":"Pause","state":"Active"}    -> heating paused
    PUT /api/modes/pause {"type":"Pause","state":"Inactive"}  -> schedule resumes
"""
from __future__ import annotations

import json
import logging
import os
import signal
import threading
import urllib.parse
import urllib.request

import paho.mqtt.client as mqtt

LOG = logging.getLogger("dlre.bridge")

PEER_URL = os.environ.get("PEER_URL", "http://peer:20558")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "30"))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "30"))

MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER") or None
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD") or None

PREFIX = os.environ.get("TOPIC_PREFIX", "danfoss-link")
DISCOVERY_PREFIX = os.environ.get("DISCOVERY_PREFIX", "homeassistant")
DEVICE_ID = os.environ.get("CC_DEVICE_ID") or None

T_AVAILABILITY = f"{PREFIX}/availability"
T_PAUSE_STATE = f"{PREFIX}/pause/state"
T_PAUSE_SET = f"{PREFIX}/pause/set"
T_MODES = f"{PREFIX}/modes"
T_ROOMS = f"{PREFIX}/rooms"
T_GRID = f"{PREFIX}/grid/state"
T_ROOM = f"{PREFIX}/room"
T_VAC_STATE = f"{PREFIX}/vacation/state"
T_VAC_SET = f"{PREFIX}/vacation/set"
T_VACTEMP_STATE = f"{PREFIX}/vacation_temp/state"
T_VACTEMP_SET = f"{PREFIX}/vacation_temp/set"
T_ONOFF = f"{PREFIX}/onoff"

DEVICE_INFO = {
    "identifiers": ["danfoss_link_cc_bridge"],
    "name": "Danfoss Link CC",
    "manufacturer": "Danfoss",
    "model": "Link CC (MDG bridge)",
}

# CC room id -> slug. The per-room HA climate entity has unique_id
# "danfoss_<slug>"; a stable id keeps the same HA entity across restarts.
ID2SLUG = {
    0: "hallway", 1: "shower", 3: "bathroom", 4: "study",
    5: "kitchen", 6: "bedroom", 7: "kids", 8: "living_room",
}


class PeerError(RuntimeError):
    pass


def peer_op(operation: str, **params) -> dict:
    """Call an operation on the MDG peer's HTTP interface."""
    url = f"{PEER_URL}/{operation}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as response:
            body = response.read().decode("utf-8", "replace")
    except Exception as exc:  # network, timeout, HTTP error
        raise PeerError(f"{operation}: {exc}") from exc
    if not body.strip():
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise PeerError(f"{operation}: non-JSON reply {body[:120]!r}") from exc


def cc_request(method: str, uri: str, content: dict | None = None) -> dict | None:
    params = {"method": method, "uri": uri}
    if content is not None:
        # Compact separators: spaces would urlencode to '+', which the peer's
        # query parser does not decode back, breaking JSON parsing on the CC.
        params["content"] = json.dumps(content, separators=(",", ":"))
    if DEVICE_ID:
        params["device_id"] = DEVICE_ID
    result = peer_op("cc-request", **params)
    if result.get("result") != "ok":
        raise PeerError(result.get("error_text", "cc-request failed"))
    return result.get("payload")


def mode_active(modes, mode_type: str) -> bool | None:
    """Whether the named house mode (Pause, Vacation, ...) is Active.

    `modes` is a GET /api/modes payload {"status":.., "content":[{"type","state"}..]};
    the content list is unwrapped before scanning. Returns None if unreadable.
    """
    if isinstance(modes, dict) and isinstance(modes.get("content"), list):
        modes = modes["content"]
    if isinstance(modes, dict):
        modes = [modes]
    if not isinstance(modes, list):
        return None
    for mode in modes:
        if isinstance(mode, dict) and str(mode.get("type", "")).lower() == mode_type.lower():
            return str(mode.get("state", "")).lower() == "active"
    return False


def publish_discovery(client: mqtt.Client) -> None:
    entities = {
        f"{DISCOVERY_PREFIX}/switch/danfoss_link/pause/config": {
            "name": "Heating pause",
            "unique_id": "danfoss_link_cc_pause",
            "command_topic": T_PAUSE_SET,
            "state_topic": T_PAUSE_STATE,
            "payload_on": "ON",
            "payload_off": "OFF",
            "icon": "mdi:pause-octagon",
            "availability_topic": T_AVAILABILITY,
            "device": DEVICE_INFO,
        },
        f"{DISCOVERY_PREFIX}/binary_sensor/danfoss_link/grid/config": {
            "name": "Grid connection",
            "unique_id": "danfoss_link_cc_grid",
            "state_topic": T_GRID,
            "payload_on": "ON",
            "payload_off": "OFF",
            "device_class": "connectivity",
            "entity_category": "diagnostic",
            "availability_topic": T_AVAILABILITY,
            "device": DEVICE_INFO,
        },
        f"{DISCOVERY_PREFIX}/switch/danfoss_link/vacation/config": {
            "name": "Vacation",
            "unique_id": "danfoss_link_cc_vacation",
            "command_topic": T_VAC_SET,
            "state_topic": T_VAC_STATE,
            "payload_on": "ON",
            "payload_off": "OFF",
            "icon": "mdi:palm-tree",
            "availability_topic": T_AVAILABILITY,
            "device": DEVICE_INFO,
        },
        f"{DISCOVERY_PREFIX}/number/danfoss_link/vacation_temp/config": {
            "name": "Vacation temperature",
            "unique_id": "danfoss_link_cc_vacation_temp",
            "command_topic": T_VACTEMP_SET,
            "state_topic": T_VACTEMP_STATE,
            "min": 5,
            "max": 35,
            "step": 0.5,
            "unit_of_measurement": "°C",
            "device_class": "temperature",
            "mode": "box",
            "availability_topic": T_AVAILABILITY,
            "device": DEVICE_INFO,
        },
    }
    for topic, payload in entities.items():
        client.publish(topic, json.dumps(payload), qos=1, retain=True)
    LOG.info("published discovery for %d entities", len(entities))


_rooms_announced: set = set()
_onoff_announced: set = set()


def publish_room_discovery(client: mqtt.Client, room: dict) -> None:
    rid = room.get("id")
    if rid is None:
        return
    slug = ID2SLUG.get(rid, f"room{rid}")
    base = f"{T_ROOM}/{rid}"
    # One climate entity per room. current_temperature, setpoint state/command
    # and mode use the per-room topics under <base>; a setpoint command lands on
    # <base>/setpoint/set, handled by _handle_setpoint.
    cfg = {
        "name": None,
        "unique_id": f"danfoss_{slug}",
        "current_temperature_topic": f"{base}/temp",
        "temperature_state_topic": f"{base}/setpoint",
        "temperature_command_topic": f"{base}/setpoint/set",
        "temperature_unit": "C",
        "min_temp": room.get("minSetpoint", 6),
        "max_temp": room.get("maxSetpoint", 35),
        "temp_step": 0.5,
        "precision": 0.5,
        "modes": ["heat"],
        "mode_state_topic": f"{base}/mode",
        "json_attributes_topic": f"{base}/attrs",
        "availability_topic": T_AVAILABILITY,
        "device": {
            "identifiers": [f"danfoss_{slug}"],
            "name": room.get("name") or slug,
            "manufacturer": "Danfoss",
            "model": "Link CC room",
        },
    }
    client.publish(f"{DISCOVERY_PREFIX}/climate/danfoss_{slug}/config",
                   json.dumps(cfg), qos=1, retain=True)


def publish_rooms(client: mqtt.Client, rooms_payload) -> None:
    """Publish per-room state from a GET /api/rooms payload.

    For each room: publishes its climate discovery once, then current
    temperature (ambientTemperature), setpoint (setpoint.temperature), mode
    ("heat") and the full room dict as JSON attributes, under <PREFIX>/room/<id>/.
    """
    content = rooms_payload.get("content") if isinstance(rooms_payload, dict) else None
    if not isinstance(content, list):
        return
    for room in content:
        if not isinstance(room, dict):
            continue
        rid = room.get("id")
        if rid is None:
            continue
        if rid not in _rooms_announced:
            publish_room_discovery(client, room)
            _rooms_announced.add(rid)
        temp = room.get("ambientTemperature")
        if temp is not None:
            client.publish(f"{T_ROOM}/{rid}/temp", json.dumps(temp), qos=0, retain=True)
        setpoint = (room.get("setpoint") or {}).get("temperature")
        if setpoint is not None:
            client.publish(f"{T_ROOM}/{rid}/setpoint", json.dumps(setpoint), qos=0, retain=True)
        client.publish(f"{T_ROOM}/{rid}/attrs", json.dumps(room), qos=0, retain=True)
        client.publish(f"{T_ROOM}/{rid}/mode", "heat", qos=0, retain=True)


def publish_onoff(client: mqtt.Client, devices) -> None:
    """Publish an HA switch per CC on/off device from a GET /api/onoffdevices
    payload, and each device's current state ("On"/"Off"). Content is a list of
    {"id","name","state"} and is empty when the CC has no on/off devices."""
    content = devices.get("content") if isinstance(devices, dict) else None
    if not isinstance(content, list):
        return
    for dev in content:
        if not isinstance(dev, dict):
            continue
        did = dev.get("id")
        if did is None:
            continue
        if did not in _onoff_announced:
            client.publish(
                f"{DISCOVERY_PREFIX}/switch/danfoss_link/onoff{did}/config",
                json.dumps({
                    "name": dev.get("name") or f"On/off {did}",
                    "unique_id": f"danfoss_link_onoff_{did}",
                    "command_topic": f"{T_ONOFF}/{did}/set",
                    "state_topic": f"{T_ONOFF}/{did}/state",
                    "payload_on": "On",
                    "payload_off": "Off",
                    "availability_topic": T_AVAILABILITY,
                    "device": DEVICE_INFO,
                }), qos=1, retain=True)
            _onoff_announced.add(did)
        state = dev.get("state")
        if state is not None:
            client.publish(f"{T_ONOFF}/{did}/state", str(state), qos=0, retain=True)


def poll_once(client: mqtt.Client) -> None:
    status = {}
    try:
        status = peer_op("status")
    except PeerError as exc:
        LOG.warning("peer unreachable: %s", exc)
        client.publish(T_AVAILABILITY, "offline", qos=1, retain=True)
        return

    connected = bool(status.get("connected_to_mdg"))
    client.publish(T_GRID, "ON" if connected else "OFF", qos=1, retain=True)
    if not connected:
        LOG.info("peer is not connected to the grid; asking it to connect")
        client.publish(T_AVAILABILITY, "offline", qos=1, retain=True)
        try:
            peer_op("connect")
        except PeerError as exc:
            LOG.warning("connect failed: %s", exc)
        return

    try:
        modes = cc_request("GET", "/api/modes")
    except PeerError as exc:
        LOG.warning("GET /api/modes failed: %s", exc)
        client.publish(T_AVAILABILITY, "offline", qos=1, retain=True)
        return

    client.publish(T_AVAILABILITY, "online", qos=1, retain=True)
    client.publish(T_MODES, json.dumps(modes), qos=0, retain=True)
    paused = mode_active(modes, "Pause")
    if paused is not None:
        client.publish(T_PAUSE_STATE, "ON" if paused else "OFF", qos=1, retain=True)
    vacation = mode_active(modes, "Vacation")
    if vacation is not None:
        client.publish(T_VAC_STATE, "ON" if vacation else "OFF", qos=1, retain=True)

    try:
        rooms = cc_request("GET", "/api/rooms")
        client.publish(T_ROOMS, json.dumps(rooms), qos=0, retain=True)
        publish_rooms(client, rooms)
    except PeerError as exc:
        LOG.debug("GET /api/rooms failed: %s", exc)

    try:
        settings = cc_request("GET", "/api/settings/temperature")
        content = settings.get("content") if isinstance(settings, dict) else None
        vac = content.get("vacationTemperature") if isinstance(content, dict) else None
        sp = vac.get("setpoint") if isinstance(vac, dict) else None
        if sp is not None:
            client.publish(T_VACTEMP_STATE, json.dumps(sp), qos=1, retain=True)
    except PeerError as exc:
        LOG.debug("GET /api/settings/temperature failed: %s", exc)

    try:
        publish_onoff(client, cc_request("GET", "/api/onoffdevices"))
    except PeerError as exc:
        LOG.debug("GET /api/onoffdevices failed: %s", exc)


def on_connect(client: mqtt.Client, userdata, flags, reason_code, properties=None):
    LOG.info("connected to MQTT (%s)", reason_code)
    client.subscribe(T_PAUSE_SET, qos=1)
    client.subscribe(T_VAC_SET, qos=1)
    client.subscribe(T_VACTEMP_SET, qos=1)
    client.subscribe(f"{T_ROOM}/+/setpoint/set", qos=1)
    client.subscribe(f"{T_ONOFF}/+/set", qos=1)
    publish_discovery(client)
    _rooms_announced.clear()
    _onoff_announced.clear()


def _handle_pause(client: mqtt.Client, payload: str) -> None:
    if payload not in ("ON", "OFF"):
        LOG.warning("ignoring pause command %r", payload)
        return
    state = "Active" if payload == "ON" else "Inactive"
    LOG.info("setting house mode Pause -> %s", state)
    params = {"state": state}
    if DEVICE_ID:
        params["device_id"] = DEVICE_ID
    try:
        result = peer_op("cc-pause", **params)
        if result.get("result") != "ok":
            raise PeerError(result.get("error_text", "cc-pause failed"))
    except PeerError as exc:
        LOG.error("pause command failed: %s", exc)
        return
    # Reflect immediately, then let the next poll confirm.
    client.publish(T_PAUSE_STATE, payload, qos=1, retain=True)
    threading.Timer(3.0, poll_once, args=(client,)).start()


def _handle_setpoint(client: mqtt.Client, topic: str, payload: str) -> None:
    # topic: <PREFIX>/room/<id>/setpoint/set -> PATCH /api/rooms/<id> setpoint
    try:
        rid = int(topic.split("/")[-3])
        value = round(float(payload) * 2) / 2  # snap to the 0.5 step
    except (ValueError, IndexError):
        LOG.warning("bad setpoint command %r on %s", payload, topic)
        return
    LOG.info("set room %s setpoint -> %s", rid, value)
    try:
        cc_request("PATCH", f"/api/rooms/{rid}", {"id": rid, "setpoint": {"temperature": value}})
    except PeerError as exc:
        LOG.error("setpoint write failed (room %s): %s", rid, exc)
        return
    client.publish(f"{T_ROOM}/{rid}/setpoint", json.dumps(value), qos=0, retain=True)
    threading.Timer(3.0, poll_once, args=(client,)).start()


def _handle_vacation(client: mqtt.Client, payload: str) -> None:
    if payload not in ("ON", "OFF"):
        LOG.warning("ignoring vacation command %r", payload)
        return
    state = "Active" if payload == "ON" else "Inactive"
    LOG.info("setting house mode Vacation -> %s", state)
    try:
        cc_request("PUT", "/api/modes/vacation", {"type": "Vacation", "state": state})
    except PeerError as exc:
        LOG.error("vacation command failed: %s", exc)
        return
    client.publish(T_VAC_STATE, payload, qos=1, retain=True)
    threading.Timer(3.0, poll_once, args=(client,)).start()


def _handle_vacation_temp(client: mqtt.Client, payload: str) -> None:
    try:
        value = round(float(payload) * 2) / 2  # snap to the 0.5 step
    except ValueError:
        LOG.warning("bad vacation temperature %r", payload)
        return
    LOG.info("set vacation temperature -> %s", value)
    try:
        cc_request("PATCH", "/api/settings/temperature",
                   {"vacationTemperature": {"setpoint": value}})
    except PeerError as exc:
        LOG.error("vacation temperature write failed: %s", exc)
        return
    client.publish(T_VACTEMP_STATE, json.dumps(value), qos=1, retain=True)
    threading.Timer(3.0, poll_once, args=(client,)).start()


def _handle_onoff(client: mqtt.Client, topic: str, payload: str) -> None:
    # topic: <PREFIX>/onoff/<id>/set -> PATCH /api/onoffdevices/<id>. The CC's
    # id type is unconfirmed (no on/off devices present to observe), so a numeric
    # id is sent as int and anything else verbatim.
    if payload not in ("On", "Off"):
        LOG.warning("ignoring on/off command %r on %s", payload, topic)
        return
    try:
        did_str = topic.split("/")[-2]
    except IndexError:
        LOG.warning("bad on/off topic %s", topic)
        return
    did = int(did_str) if did_str.lstrip("-").isdigit() else did_str
    LOG.info("set on/off device %s -> %s", did, payload)
    try:
        cc_request("PATCH", f"/api/onoffdevices/{did}", {"id": did, "state": payload})
    except PeerError as exc:
        LOG.error("on/off write failed (device %s): %s", did, exc)
        return
    client.publish(f"{T_ONOFF}/{did}/state", payload, qos=0, retain=True)
    threading.Timer(3.0, poll_once, args=(client,)).start()


def on_message(client: mqtt.Client, userdata, message: mqtt.MQTTMessage):
    topic = message.topic
    raw = message.payload.decode("utf-8", "replace").strip()
    if not topic.startswith(f"{PREFIX}/"):
        return
    # Match on the path segments after the prefix: "<kind>[/<id>]/set".
    # PREFIX may itself contain "/", so strip it before splitting.
    match topic.removeprefix(f"{PREFIX}/").split("/"):
        case ["pause", "set"]:
            _handle_pause(client, raw.upper())
        case ["vacation", "set"]:
            _handle_vacation(client, raw.upper())
        case ["vacation_temp", "set"]:
            _handle_vacation_temp(client, raw)
        case ["room", _, "setpoint", "set"]:
            _handle_setpoint(client, topic, raw)
        case ["onoff", _, "set"]:
            _handle_onoff(client, topic, raw)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )

    # VERSION2 callbacks: paho 2.x deprecates the v1 signatures.
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="danfoss-link-bridge",
        protocol=mqtt.MQTTv311,
    )
    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.will_set(T_AVAILABILITY, "offline", qos=1, retain=True)
    client.on_connect = on_connect
    client.on_message = on_message

    stopping = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopping.set())

    while not stopping.is_set():
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
            break
        except OSError as exc:
            LOG.warning("MQTT connect failed (%s); retrying in 5s", exc)
            stopping.wait(5)

    client.loop_start()
    try:
        while not stopping.is_set():
            poll_once(client)
            stopping.wait(POLL_SECONDS)
    finally:
        client.publish(T_AVAILABILITY, "offline", qos=1, retain=True)
        client.loop_stop()
        client.disconnect()
        LOG.info("stopped")


if __name__ == "__main__":
    main()
