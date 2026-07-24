#!/bin/bash
# Run on a machine whose IP is allowlisted on Vultr (usually your home PC).
# Creates 5 Squid proxy VPS across regions and writes proxies.txt
#
#   export VULTR_API_KEY='your-key'
#   bash vultr_deploy_local.sh
#   bash vultr_deploy_local.sh destroy

set -euo pipefail

API="https://api.vultr.com/v2"
KEY="${VULTR_API_KEY:?export VULTR_API_KEY first}"
PLAN="${VULTR_PLAN:-vc2-1c-1gb}"
OS_ID="${VULTR_OS_ID:-1743}"
OUT="${PROXY_FILE:-proxies.txt}"
IDS_FILE=".vultr_proxy_ids"
LABEL_PREFIX="pixieset-proxy"
REGIONS=(ewr lax fra sgp syd)

auth=(-H "Authorization: Bearer $KEY" -H "Content-Type: application/json")

USER_DATA_B64=$(python3 - <<'PY'
import base64
script = """#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq squid
cat >/etc/squid/conf.d/open.conf <<'SQUID'
http_port 3128
acl all src 0.0.0.0/0
http_access allow all
SQUID
sed -i 's/^http_access deny all/# http_access deny all/' /etc/squid/squid.conf || true
systemctl enable squid
systemctl restart squid
ufw allow 3128/tcp 2>/dev/null || true
"""
print(base64.b64encode(script.encode()).decode(), end="")
PY
)

api() {
  local method="$1" path="$2" data="${3:-}"
  if [ -n "$data" ]; then
    curl -sS -X "$method" "${auth[@]}" -d "$data" "$API$path"
  else
    curl -sS -X "$method" "${auth[@]}" "$API$path"
  fi
}

check_auth() {
  local resp http body
  resp=$(curl -sS -w "\n%{http_code}" "${auth[@]}" "$API/account")
  http=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | sed '$d')
  if [ "$http" != "200" ]; then
    echo "[!] Auth failed (HTTP $http)"
    echo "$body"
    echo "Enable Vultr Access Control → Any IPv4 (0.0.0.0/0), or allowlist $(curl -s https://api.ipify.org)/32"
    exit 1
  fi
  echo "[+] API auth OK"
}

deploy() {
  check_auth
  : > "$IDS_FILE"
  : > "$OUT"
  echo "[*] Deploying ${#REGIONS[@]} instances ($PLAN)..."

  for region in "${REGIONS[@]}"; do
    label="${LABEL_PREFIX}-${region}-$(date +%s)"
    payload=$(cat <<JSON
{"region":"$region","plan":"$PLAN","os_id":$OS_ID,"label":"$label","hostname":"proxy-$region","user_data":"$USER_DATA_B64","backups":"disabled"}
JSON
)
    echo "[*] Creating $label in $region..."
    resp=$(api POST /instances "$payload")
    id=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('instance',{}).get('id',''))" 2>/dev/null || true)
    if [ -z "$id" ]; then
      echo "[!] Failed: $resp"
      continue
    fi
    echo "$id $region" >> "$IDS_FILE"
    echo "    id=$id"
  done

  echo "[*] Waiting for IPs + Squid..."
  declare -A IPS
  for attempt in $(seq 1 40); do
    while read -r id region; do
      [ -z "$id" ] && continue
      [ -n "${IPS[$id]:-}" ] && continue
      info=$(api GET "/instances/$id")
      ip=$(echo "$info" | python3 -c "import sys,json; i=json.load(sys.stdin).get('instance',{}); print(i.get('main_ip','') if i.get('main_ip') not in ('', '0.0.0.0', None) else '')" 2>/dev/null || true)
      if [ -n "$ip" ] && curl -sS -m 8 -x "http://$ip:3128" https://api.ipify.org >/tmp/proxy_ip_test 2>/dev/null; then
        echo "[+] $region $ip:3128  egress=$(cat /tmp/proxy_ip_test)"
        echo "http://$ip:3128" >> "$OUT"
        IPS[$id]="$ip"
      fi
    done < "$IDS_FILE"
    count=$(wc -l < "$OUT" | tr -d ' ')
    want=$(wc -l < "$IDS_FILE" | tr -d ' ')
    [ "$count" -ge "$want" ] && [ "$want" -gt 0 ] && break
    sleep 6
  done

  echo ""
  echo "========== READY =========="
  cat "$OUT"
  echo "==========================="
  echo "python3 pixieset_cracker.py -u site.pixieset.com -g jill --proxy-file $OUT"
  echo "bash vultr_deploy_local.sh destroy   # stop billing"
}

destroy() {
  check_auth
  if [ -f "$IDS_FILE" ]; then
    while read -r id region; do
      [ -z "$id" ] && continue
      echo "[*] Destroying $id ($region)"
      api DELETE "/instances/$id" >/dev/null || true
    done < "$IDS_FILE"
    rm -f "$IDS_FILE"
  else
    api GET "/instances?per_page=100" | python3 -c "
import sys,json
for i in json.load(sys.stdin).get('instances',[]):
    if i.get('label','').startswith('$LABEL_PREFIX'):
        print(i['id'])
" | while read -r id; do
      echo "[*] Destroying $id"
      api DELETE "/instances/$id" >/dev/null || true
    done
  fi
  rm -f "$OUT"
  echo "[+] Destroy done"
}

list_proxies() {
  check_auth
  api GET "/instances?per_page=100" | python3 -c "
import sys,json
for i in json.load(sys.stdin).get('instances',[]):
    if i.get('label','').startswith('$LABEL_PREFIX'):
        print(f\"{i.get('label'):40s} {i.get('main_ip'):16s} {i.get('region'):5s} {i.get('status')}\")
"
}

case "${1:-deploy}" in
  deploy)  deploy ;;
  destroy) destroy ;;
  list)    list_proxies ;;
  *) echo "Usage: $0 [deploy|destroy|list]"; exit 1 ;;
esac
