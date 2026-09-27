#!/usr/bin/env bash
# One-command live demo: records real VPN traffic and analyzes it.
# Usage: ./live-demo.sh [seconds, default 10]
SECS=${1:-10}
cd "$(dirname "$0")" || exit 1
echo "== 1. capture rights (password once) =="
sudo setcap cap_net_raw,cap_net_admin+eip "$(which tcpdump)" 2>/dev/null || true
echo "== 2. wake VPN =="
sudo docker start vpn-server vpn-client >/dev/null 2>&1 || true
sleep 2
echo "== 3. recording $SECS s — pinging VPN at the same time =="
curl -s -X POST http://127.0.0.1:8000/api/live/capture \
  -H "Content-Type: application/json" \
  -d "{\"seconds\": $SECS, \"filter\": \"esp or udp port 500 or udp port 4500\", \"iface\": \"any\"}" > /tmp/live-out.json &
CURL_PID=$!
sleep 2
sudo docker exec vpn-client ping -c "$SECS" 10.10.0.10 2>&1 | tail -n 3
wait $CURL_PID
echo "== 4. result =="
python3 -c "
import json
d = json.load(open('/tmp/live-out.json'))
o, s = d['observed'], d['security']
print('packets:', o['packet_count'], '| ESP:', o['esp_packets'], '| risk:', s['risk'])
print('open Dashboard → History →', d['capture_id'])
"
