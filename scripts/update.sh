#!/bin/bash
#
# HM1K Server Update Script
# Run from audit user's home directory: ~/update.sh
#
# Safely updates the Hash Master 1000 server:
# 1. Stops the service
# 2. Pulls latest code from git
# 3. Updates Python dependencies
# 4. Restarts the service
#

set -e  # Exit on any error

# Configuration
APP_DIR="/opt/hm1k"
VENV_DIR="$APP_DIR/.venv"
SERVICE_NAME="hm1k"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as audit user or with sudo capability
check_permissions() {
    if ! sudo -n true 2>/dev/null; then
        log_error "This script requires sudo privileges. Please run with a user that has sudo access."
        exit 1
    fi
}

# Stop the service
stop_service() {
    log_info "Stopping $SERVICE_NAME service..."
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        sudo systemctl stop "$SERVICE_NAME"
        log_info "Service stopped"
    else
        log_warn "Service was not running"
    fi
}

# Pull latest code
update_code() {
    log_info "Pulling latest code from git..."
    cd "$APP_DIR"

    # Check for local changes
    if ! git diff --quiet 2>/dev/null; then
        log_warn "Local changes detected. Stashing..."
        git stash
    fi

    # Pull latest
    git fetch origin
    git reset --hard origin/main

    log_info "Code updated to: $(git log -1 --pretty=format:'%h - %s')"
}

# Update Python dependencies
update_dependencies() {
    log_info "Updating Python dependencies..."

    if [[ ! -d "$VENV_DIR" ]]; then
        log_error "Virtual environment not found at $VENV_DIR"
        exit 1
    fi

    source "$VENV_DIR/bin/activate"
    pip install --quiet --upgrade pip
    pip install --quiet -r "$APP_DIR/requirements.txt"
    deactivate

    log_info "Dependencies updated"
}

# Sync systemd service file if changed
sync_service_file() {
    local repo_service="$APP_DIR/docs/systemd/hm1k.service"
    local system_service="/etc/systemd/system/hm1k.service"

    if [[ ! -f "$repo_service" ]]; then
        log_warn "Service file not found in repo: $repo_service"
        return
    fi

    # Check if service file differs
    if ! diff -q "$repo_service" "$system_service" >/dev/null 2>&1; then
        log_info "Syncing systemd service file..."
        sudo cp "$repo_service" "$system_service"
        sudo systemctl daemon-reload
        log_info "Service file updated"
    fi
}

# Start the service
start_service() {
    log_info "Starting $SERVICE_NAME service..."
    sudo systemctl start "$SERVICE_NAME"

    # Wait a moment and check status
    sleep 2
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Service started successfully"
    else
        log_error "Service failed to start. Check logs with: sudo journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
}

# Show service status
show_status() {
    echo ""
    log_info "Service status:"
    sudo systemctl status "$SERVICE_NAME" --no-pager | head -15
}

# Main execution
main() {
    echo "=========================================="
    echo "  HM1K Server Update"
    echo "=========================================="
    echo ""

    check_permissions
    stop_service
    update_code
    update_dependencies
    sync_service_file
    start_service
    show_status

    echo ""
    log_info "Update complete!"
}

main "$@"
