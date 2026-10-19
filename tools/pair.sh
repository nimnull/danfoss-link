#!/bin/sh
# One-time pairing with the Danfoss Link CC.
#
#  1. On the CC: Settings -> Internet/App access -> allow pairing. It shows a
#     5-digit OTP and stays in pairing mode for a couple of minutes.
#  2. Run:  tools/pair.sh 12345
#
# Pairing goes through the grid (pair-remote), so the CC only needs internet,
# not the same LAN. For a LAN pairing use pair-local with the CC's IP.
set -eu
PEER=${PEER:-http://127.0.0.1:20558}
OTP=${1:?usage: pair.sh <otp-from-cc> [cc-ip]}
IP=${2:-}

printf 'peer identity: '; curl -sS --max-time 5 "$PEER/whoami"; echo
curl -sS --max-time 5 "$PEER/connect" >/dev/null || true

for _ in $(seq 20); do
  case "$(curl -sS --max-time 5 "$PEER/status")" in
    *'"connected_to_mdg":true'*) break ;;
  esac
  sleep 1
done
printf 'status: '; curl -sS --max-time 5 "$PEER/status"; echo

if [ -n "$IP" ]; then
  echo "pairing over LAN with $IP ..."
  curl -sS --max-time 40 "$PEER/pair-local?ip=$IP&otp=$OTP"; echo
else
  echo "pairing over the grid ..."
  curl -sS --max-time 40 "$PEER/pair-remote?otp=$OTP"; echo
fi

printf 'pairings: '; curl -sS --max-time 10 "$PEER/pairings"; echo
echo
echo 'smoke test:'
curl -sS --max-time 30 "$PEER/cc-request?method=GET&uri=/api/modes"; echo
