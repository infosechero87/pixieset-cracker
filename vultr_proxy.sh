#!/bin/bash
# Vultr disposable proxy launcher
# Requires: VULTR_API_KEY env var, curl, jq
# Usage: ./vultr_proxy.sh deploy 3    # spin up 3 proxy VPSes
#        ./vultr_proxy.sh list        # list proxy IPs
#        ./vultr_proxy.sh destroy     # destroy all proxy VPSes

VULTR_API="https://api.vultr.com/v2"
API_KEY="${VULTR_API_KEY:?Set VULTR_API_KEY}"
REGION="${VULTR_REGION:-ewr}"          # Newark default
PLAN="${VULTR_PLAN:-vc2-1c-1gb}"      # $6/mo, smallest
OS_ID="${VULTR_OS_ID:-1743}"          # Ubuntu 22.04 LTS
LABEL_PREFIX="pixieset-proxy"
PROXY_PORT="${PROXY_PORT:-3128}"
PROXY_FILE="vultr_proxies.txt"

_auth() { echo "Authorization: Bearer $API_KEY"; }

deploy() {
    local count="${1:-1}"
    echo "[*] Deploying $count VPS instance(s) in $REGION..."
    > "$PROXY_FILE"

    for i in $(seq 1 "$count"); do
        local label="${LABEL_PREFIX}-${i}-$(date +%s)"
        echo "[*] Creating $label ..."

        local resp=$(curl -s -H "$(_auth)" -H "Content-Type: application/json" \
            -X POST "$VULTR_API/instances" \
            -d "{\"region\":\"$REGION\",\"plan\":\"$PLAN\",\"os_id\":$OS_ID,\"label\":\"$label\"}")

        local inst_id=$(echo "$resp" | jq -r '.instance.id // empty')
        if [ -z "$inst_id" ]; then
            echo "[!] Failed: $resp"
            continue
        fi
        echo "[*] Instance $inst_id created. Waiting for IP..."

        # Poll for IP
        for _ in $(seq 1 30); do
            sleep 5
            local ip=$(curl -s -H "$(_auth)" "$VULTR_API/instances/$inst_id" | jq -r '.instance.main_ip // empty')
            if [ -n "$ip" ] && [ "$ip" != "0.0.0.0" ]; then
                echo "[+] $label → $ip"
                echo "$ip" >> "$PROXY_FILE"
                break
            fi
        done

        # Bootstrap: install squid + auto-setup via cloud-init would be cleaner,
        # but we SSH bootstrap post-deploy for simplicity
        if [ -n "$SETUP_SCRIPT" ] && [ -f "$SETUP_SCRIPT" ]; then
            echo "[*] Running setup on $ip..."
            ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 "root@$ip" "bash -s" < "$SETUP_SCRIPT" &
        fi
    done

    echo "[+] Saved IPs to $PROXY_FILE"
    generate_squid_config
}

generate_squid_config() {
    echo "[*] Run this on each VPS to install Squid:"
    echo "    apt update && apt install -y squid"
    echo "    sed -i 's/http_access deny all/http_access allow all/' /etc/squid/squid.conf"
    echo "    systemctl restart squid"
}

list() {
    echo "[*] Active Pixieset proxy instances:"
    curl -s -H "$(_auth)" "$VULTR_API/instances" | \
        jq -r '.instances[] | select(.label | startswith("'"$LABEL_PREFIX"'")) | "\(.label)  \(.main_ip)  \(.status)"'
}

destroy() {
    echo "[*] Destroying all Pixieset proxy instances..."
    local ids=$(curl -s -H "$(_auth)" "$VULTR_API/instances" | \
        jq -r '.instances[] | select(.label | startswith("'"$LABEL_PREFIX"'")) | .id')

    for id in $ids; do
        echo "[*] Destroying $id..."
        curl -s -H "$(_auth)" -X DELETE "$VULTR_API/instances/$id"
    done
    rm -f "$PROXY_FILE"
    echo "[+] Done"
}

# Setup script for auto-provisioning Squid on each VPS
write_setup_script() {
    cat > /tmp/vultr_squid_setup.sh << 'SETUP_EOF'
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
apt update -qq && apt install -y -qq squid > /dev/null 2>&1
cat > /etc/squid/conf.d/pixieset.conf << 'SQUID_EOF'
http_port 3128
acl all src 0.0.0.0/0
http_access allow all
SQUID_EOF
systemctl restart squid
echo "[+] Squid ready on $(curl -s ifconfig.me):3128"
SETUP_EOF
    chmod +x /tmp/vultr_squid_setup.sh
    echo "/tmp/vultr_squid_setup.sh"
}

case "${1:-}" in
    deploy)
        deploy "${2:-1}"
        ;;
    list)
        list
        ;;
    destroy)
        destroy
        ;;
    setup-script)
        write_setup_script
        ;;
    *)
        echo "Usage: $0 {deploy <count>|list|destroy|setup-script}"
        echo ""
        echo "Environment:"
        echo "  VULTR_API_KEY   Vultr API key (required)"
        echo "  VULTR_REGION    Datacenter region (default: ewr)"
        echo "  VULTR_PLAN      Instance plan (default: vc2-1c-1gb)"
        echo ""
        echo "Example:"
        echo "  export VULTR_API_KEY=your-key"
        echo "  ./vultr_proxy.sh deploy 3     # spin up 3 proxies"
        echo "  ./vultr_proxy.sh list          # see IPs"
        echo "  ./vultr_proxy.sh destroy       # tear down"
        ;;
esac
