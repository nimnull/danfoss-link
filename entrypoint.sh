#!/bin/bash
# dlre-helper: run the vendor Lua MDG peer and the Python MQTT bridge in one
# container. Peer first (holds the grid connection + HTTP gateway on :20558),
# then the bridge once the peer is grid-connected. Exit if either child dies so
# Docker's restart policy recycles the whole unit.
set -u

lua5.1 /peer/main.lua &
PEER_PID=$!
echo "[helper] peer started pid=$PEER_PID; waiting for grid connect..."

ok=0
for i in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:20558/status" 2>/dev/null | grep -q '"connected_to_mdg":true'; then
    ok=1; break
  fi
  kill -0 "$PEER_PID" 2>/dev/null || { echo "[helper] peer exited before connecting"; exit 1; }
  sleep 2
done
[ "$ok" = 1 ] && echo "[helper] peer grid-connected" \
             || echo "[helper] peer not connected yet; starting bridge anyway (it retries)"

/opt/br/bin/python /bridge/mqtt_bridge.py &
BR_PID=$!
echo "[helper] bridge started pid=$BR_PID"

# recycle the whole container if either process exits
wait -n
echo "[helper] a child exited; stopping the other and recycling"
kill "$PEER_PID" "$BR_PID" 2>/dev/null || true
exit 1
