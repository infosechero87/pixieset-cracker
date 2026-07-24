#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Pixieset Cracker — Ubuntu Deployment Script
# =============================================================================
# One-command deployment for fresh Ubuntu 20.04/22.04/24.04 servers.
#
# Usage:
#   chmod +x deploy.sh && ./deploy.sh
#
# Or deploy directly from GitHub:
#   curl -sSL https://raw.githubusercontent.com/infosechero87/pixieset-cracker/main/deploy.sh | bash
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; exit 1; }

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════╗"
echo "║   Pixieset Cracker — Ubuntu Deploy           ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

# --- Detect Ubuntu version ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    log "Detected: $NAME $VERSION_ID"
else
    warn "Could not detect OS — assuming Ubuntu 22.04+"
fi

# --- System updates ---
log "Updating system packages..."
sudo apt-get update -qq && sudo apt-get upgrade -y -qq

# --- Install system dependencies ---
log "Installing system dependencies..."
sudo apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    tor \
    proxychains4

# --- Install optional browser automation deps (for --browser mode) ---
log "Installing Chromium for browser mode..."
if ! command -v chromium-browser &>/dev/null && ! command -v chromium &>/dev/null; then
    sudo apt-get install -y -qq chromium-browser || \
        warn "Chromium install failed — browser mode won't work. Install manually if needed."
fi

# --- Clone or update repo ---
REPO_DIR="$HOME/pixieset-cracker"
if [ -d "$REPO_DIR/.git" ]; then
    log "Repository exists, pulling latest..."
    cd "$REPO_DIR" && git pull
else
    log "Cloning repository..."
    git clone https://github.com/infosechero87/pixieset-cracker.git "$REPO_DIR"
    cd "$REPO_DIR"
fi

# --- Python virtual environment ---
if [ ! -d "$REPO_DIR/venv" ]; then
    log "Creating Python virtual environment..."
    python3 -m venv "$REPO_DIR/venv"
fi
source "$REPO_DIR/venv/bin/activate"

# --- Python dependencies ---
log "Installing Python dependencies..."
pip install --upgrade pip -q
pip install curl_cffi -q

# --- Quick smoke test ---
log "Running smoke test..."
python3 -c "
from pixieset_cracker import PixiesetCracker, generate_passwords
pwds = generate_passwords('test')
assert len(pwds) > 10, 'Password generation failed'
print('  ✓ Password generation: OK')
print('  ✓ Imports: OK')
" || err "Smoke test failed — check Python dependencies"

# --- Configure proxychains for Tor (optional) ---
log "Setting up proxychains + Tor..."
if ! systemctl is-active --quiet tor 2>/dev/null; then
    sudo systemctl enable --now tor 2>/dev/null || \
        warn "Tor service setup failed — run manually: sudo systemctl start tor"
fi

if [ -f /etc/proxychains4.conf ]; then
    # Ensure Tor SOCKS5 is in proxychains config
    if ! grep -q "socks5 127.0.0.1 9050" /etc/proxychains4.conf; then
        warn "proxychains config may need manual Tor entry (socks5 127.0.0.1 9050)"
    fi
else
    warn "proxychains4 config not found — install with: sudo apt install proxychains4"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Deployment Complete!                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Tool location:${NC} $REPO_DIR/pixieset_cracker.py"
echo -e "  ${CYAN}Venv:${NC}          source $REPO_DIR/venv/bin/activate"
echo ""
echo -e "  ${CYAN}Quick start:${NC}"
echo -e "    cd $REPO_DIR && source venv/bin/activate"
echo -e "    python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill"
echo ""
echo -e "  ${CYAN}With proxy rotation:${NC}"
echo -e "    python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill --proxy"
echo ""
echo -e "  ${CYAN}Via Tor (proxychains):${NC}"
echo -e "    proxychains4 python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill"
echo ""
echo -e "  ${CYAN}Discover galleries:${NC}"
echo -e "    python3 pixieset_cracker.py -u subdomain.pixieset.com --discover -f slugs.txt"
echo ""
echo -e "  ${CYAN}Pre-fetch proxy pool (faster startup):${NC}"
echo -e "    python3 proxy_rotator.py --export proxies.json"
echo -e "    python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill --proxy --proxy-file proxies.json"
echo ""
