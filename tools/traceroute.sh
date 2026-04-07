#!/usr/bin/env bash
# Validates Check C (router-egress traceroute) on a USB-connected Android
# device using the on-device /system/bin/ping binary. No root, no APK
# required. Handy after every router change to confirm the egress path.
#
# Usage:
#   tools/traceroute.sh                       # default: trace to 1.1.1.1, 15 hops
#   tools/traceroute.sh 8.8.8.8               # trace to 8.8.8.8
#   tools/traceroute.sh 1.1.1.1 25            # 25 hops
#   tools/traceroute.sh 1.1.1.1 15 <serial>   # specific device
#
# Output: per-hop IP, then a ipinfo.io country/city/ASN lookup for every
# unique non-RFC1918 hop.

# Note: no `set -e` — `grep -c` returns 1 when nothing matches, which is
# not an error here. We handle missing fields explicitly.
TARGET=${1:-1.1.1.1}
MAX=${2:-15}
SERIAL=${3:-}
DEV_FLAG=()
[ -n "$SERIAL" ] && DEV_FLAG=(-s "$SERIAL")

echo "=== route table on phone ==="
adb "${DEV_FLAG[@]}" shell 'ip route show table all 2>&1 | grep -E "^default|192.168|10\."' | head -10
echo
echo "=== wifi link ==="
adb "${DEV_FLAG[@]}" shell 'ip -4 addr show wlan0 2>/dev/null | grep inet'
echo
echo "=== TTL traceroute to $TARGET ==="
hops=()
for ttl in $(seq 1 "$MAX"); do
  out=$(adb "${DEV_FLAG[@]}" shell "/system/bin/ping -c 1 -W 1 -n -t $ttl $TARGET 2>&1")
  hop=$(echo "$out" | grep -oE 'From [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|bytes from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
  reached=$(echo "$out" | grep -c '1 received')
  printf "  hop %2d: %-16s reached=%s\n" "$ttl" "${hop:-*}" "$reached"
  [ -n "$hop" ] && hops+=("$hop")
  [ "$reached" = "1" ] && break
done

# Lookup unique public hops via ipinfo.io
echo
echo "=== GeoIP for non-RFC1918 hops ==="
seen=()
for ip in "${hops[@]}"; do
  case "$ip" in
    10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|169.254.*|127.*) continue ;;
  esac
  # dedupe
  for s in "${seen[@]}"; do [ "$s" = "$ip" ] && continue 2; done
  seen+=("$ip")
  printf "  %-16s  " "$ip"
  curl -sS "https://ipinfo.io/$ip/json" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print(d.get("country", "?"), d.get("city", "?"), "|", d.get("org", "?"))
'
done
