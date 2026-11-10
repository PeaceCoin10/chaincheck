#!/usr/bin/env bash
# Keep chaincheck + its public tunnel alive. Idempotent: safe to run every minute.
set -u
cd "$(dirname "$0")/.."
mkdir -p logs

if ! pgrep -f "node src/server.mjs" >/dev/null; then
  env -u http_proxy -u https_proxy -u all_proxy PORT=4021 setsid node src/server.mjs \
    >> logs/server.log 2>&1 < /dev/null &
  echo "$(date -Is) started server"
fi

if ! pgrep -f "cloudflared tunnel --url http://127.0.0.1:4021" >/dev/null; then
  env -u http_proxy -u https_proxy -u all_proxy cloudflared tunnel \
    --url http://127.0.0.1:4021 --no-autoupdate >> logs/tunnel.log 2>&1 < /dev/null &
  echo "$(date -Is) started tunnel"
fi

sleep 3
URL=$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' logs/tunnel.log | tail -1)
if [ -n "$URL" ]; then
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$URL/health")
  echo "$(date -Is) $URL health=$CODE"
  echo "$URL" > PUBLIC-URL.txt
fi
