#!/bin/bash
#
# HM1K Agent Bootstrap Installer
# Downloads and installs the HM1K hashcat cracking agent
#
# Usage: curl -sSL https://192.168.8.88/agent/install.sh | sudo bash
#
# Or download and run manually:
#   wget https://192.168.8.88/agent/install.sh
#   chmod +x install.sh
#   sudo ./install.sh
#

set -e

# Configuration
HM1K_SERVER="${HM1K_SERVER:-https://192.168.8.88}"
AGENT_BASE_URL="${HM1K_SERVER}/agent"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

echo ""
echo "=============================================="
echo "     HM1K Agent Bootstrap Installer"
echo "=============================================="
echo ""
log_info "Server: $HM1K_SERVER"
log_info "Temp directory: $TEMP_DIR"
echo ""

# Download files
log_info "Downloading agent files..."

# Use curl with -k to skip SSL verification for self-signed certs
CURL_OPTS="-sSL -k"

curl $CURL_OPTS "${AGENT_BASE_URL}/deploy.sh" -o "$TEMP_DIR/deploy.sh" || {
    log_error "Failed to download deploy.sh"
    exit 1
}
log_success "Downloaded deploy.sh"

curl $CURL_OPTS "${AGENT_BASE_URL}/hm1k_agent-0.1.0-py3-none-any.whl" -o "$TEMP_DIR/hm1k_agent-0.1.0-py3-none-any.whl" || {
    log_error "Failed to download agent wheel"
    exit 1
}
log_success "Downloaded agent wheel"

curl $CURL_OPTS "${AGENT_BASE_URL}/config.example.yaml" -o "$TEMP_DIR/config.example.yaml" || {
    log_error "Failed to download config.example.yaml"
    exit 1
}
log_success "Downloaded config.example.yaml"

# Make deploy.sh executable
chmod +x "$TEMP_DIR/deploy.sh"

# Run the deployment
log_info "Running deployment script..."
echo ""

cd "$TEMP_DIR"
./deploy.sh "$@"

echo ""
log_success "Bootstrap installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/hm1k-agent/config.yaml with your agent settings"
echo "  2. Run: sudo hm1k-agent init"
echo "  3. Run: sudo systemctl enable --now hm1k-agent"
echo ""
