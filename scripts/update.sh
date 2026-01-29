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
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Track timing
SCRIPT_START=$(date +%s)

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}${BOLD}▶ $1${NC}"
}

log_detail() {
    echo -e "  ${CYAN}→${NC} $1"
}

log_cmd() {
    echo -e "  ${CYAN}\$${NC} $1"
}

# Check if running as audit user or with sudo capability
check_permissions() {
    log_step "Checking permissions"
    if ! sudo -n true 2>/dev/null; then
        log_error "This script requires sudo privileges. Please run with a user that has sudo access."
        exit 1
    fi
    log_detail "Sudo access: OK"
    log_detail "Running as: $(whoami)"
}

# Stop the service
stop_service() {
    log_step "Stopping $SERVICE_NAME service"

    log_cmd "systemctl is-active $SERVICE_NAME"
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        local pid=$(sudo systemctl show -p MainPID --value "$SERVICE_NAME")
        log_detail "Service is running (PID: $pid)"

        log_cmd "systemctl stop $SERVICE_NAME"
        local stop_start=$(date +%s)
        sudo systemctl stop "$SERVICE_NAME"
        local stop_end=$(date +%s)
        log_detail "Service stopped in $((stop_end - stop_start))s"
    else
        log_warn "Service was not running"
    fi
}

# Pull latest code
update_code() {
    log_step "Updating code from git"
    cd "$APP_DIR"

    local current_commit=$(git rev-parse --short HEAD)
    log_detail "Current commit: $current_commit"

    # Check for local changes
    if ! git diff --quiet 2>/dev/null; then
        log_warn "Local changes detected"
        log_cmd "git stash"
        git stash
    fi

    # Fetch and show what's coming
    log_cmd "git fetch origin"
    git fetch origin

    local remote_commit=$(git rev-parse --short origin/main)
    local commits_behind=$(git rev-list HEAD..origin/main --count)

    if [[ "$commits_behind" -gt 0 ]]; then
        log_detail "Commits to apply: $commits_behind"
        log_detail "New commits:"
        git log --oneline HEAD..origin/main | head -5 | while read line; do
            echo -e "    ${CYAN}•${NC} $line"
        done
        if [[ "$commits_behind" -gt 5 ]]; then
            echo -e "    ${CYAN}...and $((commits_behind - 5)) more${NC}"
        fi
    else
        log_detail "Already up to date"
    fi

    # Pull latest
    log_cmd "git reset --hard origin/main"
    git reset --hard origin/main

    log_detail "Updated to: $(git log -1 --pretty=format:'%h - %s')"
}

# Update Python dependencies
update_dependencies() {
    log_step "Updating Python dependencies"

    if [[ ! -d "$VENV_DIR" ]]; then
        log_error "Virtual environment not found at $VENV_DIR"
        exit 1
    fi

    log_detail "Activating venv: $VENV_DIR"
    source "$VENV_DIR/bin/activate"

    log_cmd "pip install --upgrade pip"
    pip install --quiet --upgrade pip

    log_cmd "pip install -r requirements.txt"
    local pip_start=$(date +%s)
    pip install --quiet -r "$APP_DIR/requirements.txt"
    local pip_end=$(date +%s)

    deactivate
    log_detail "Dependencies updated in $((pip_end - pip_start))s"
}

# Build agent wheel package
build_agent_wheel() {
    log_step "Building agent wheel package"

    local agent_dir="$APP_DIR/internal/hm1k-agent"

    if [[ ! -d "$agent_dir" ]]; then
        log_warn "Agent directory not found at $agent_dir"
        return
    fi

    cd "$agent_dir"

    # Activate venv to use build module
    source "$VENV_DIR/bin/activate"

    # Ensure build module and hatchling backend are installed
    log_cmd "pip install build hatchling"
    if ! pip install --quiet build hatchling 2>&1; then
        log_warn "Failed to install build tools"
        deactivate
        cd "$APP_DIR"
        return
    fi

    # Create dist directory if needed
    mkdir -p dist/

    # Build the wheel
    log_cmd "python -m build --wheel"
    local build_start=$(date +%s)
    local build_output
    if build_output=$(python -m build --wheel --outdir dist/ 2>&1); then
        local build_end=$(date +%s)
        local wheel_file=$(ls -t dist/*.whl 2>/dev/null | head -1)
        log_detail "Wheel built in $((build_end - build_start))s"
        if [[ -n "$wheel_file" ]]; then
            log_detail "Package: $(basename $wheel_file)"
        fi
    else
        log_warn "Failed to build agent wheel (non-critical)"
        log_detail "Build output: $(echo "$build_output" | tail -3)"
    fi

    deactivate
    cd "$APP_DIR"
}

# Sync systemd service file if changed
sync_service_file() {
    log_step "Checking systemd service file"

    local repo_service="$APP_DIR/docs/systemd/hm1k.service"
    local system_service="/etc/systemd/system/hm1k.service"

    if [[ ! -f "$repo_service" ]]; then
        log_warn "Service file not found in repo: $repo_service"
        return
    fi

    # Check if service file differs
    if ! diff -q "$repo_service" "$system_service" >/dev/null 2>&1; then
        log_detail "Service file has changed"
        log_cmd "cp $repo_service $system_service"
        sudo cp "$repo_service" "$system_service"
        log_cmd "systemctl daemon-reload"
        sudo systemctl daemon-reload
        log_detail "Service file synced and daemon reloaded"
    else
        log_detail "Service file unchanged"
    fi
}

# Start the service
start_service() {
    log_step "Starting $SERVICE_NAME service"

    log_cmd "systemctl start $SERVICE_NAME"
    local start_time=$(date +%s)
    sudo systemctl start "$SERVICE_NAME"

    # Wait for workers to initialize
    log_detail "Waiting for workers to initialize..."
    sleep 3
    local end_time=$(date +%s)

    log_cmd "systemctl is-active $SERVICE_NAME"
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        log_detail "Service started in $((end_time - start_time))s"

        # Get detailed status
        local main_pid=$(sudo systemctl show -p MainPID --value "$SERVICE_NAME")
        local memory=$(sudo systemctl show -p MemoryCurrent --value "$SERVICE_NAME")
        local worker_count=$(pgrep -c -f "gunicorn.*$SERVICE_NAME" 2>/dev/null || echo "?")

        log_detail "Main PID: $main_pid"
        log_detail "Memory usage: $(numfmt --to=iec-i --suffix=B $memory 2>/dev/null || echo $memory)"
        log_detail "Gunicorn processes: $worker_count (1 master + $((worker_count - 1)) workers)"
    else
        log_error "Service failed to start!"
        log_cmd "journalctl -u $SERVICE_NAME -n 20 --no-pager"
        sudo journalctl -u "$SERVICE_NAME" -n 20 --no-pager
        exit 1
    fi
}

# Show service status
show_status() {
    log_step "Service status"

    echo ""
    sudo systemctl status "$SERVICE_NAME" --no-pager -l 2>/dev/null | head -20

    # Show worker PIDs
    echo ""
    log_detail "Worker processes:"
    ps -eo pid,ppid,user,%mem,%cpu,etime,args --sort=-%mem | grep "gunicorn.*$SERVICE_NAME" | grep -v grep | head -15 | while read line; do
        echo -e "    $line"
    done
}

# Health check
health_check() {
    log_step "Health check"

    log_cmd "curl -sk https://127.0.0.1:8443/api/health/liveness"

    # Retry up to 5 times with 2 second delay to allow server to start
    local max_attempts=5
    local attempt=1
    local health_response=""

    while [[ $attempt -le $max_attempts ]]; do
        log_detail "Checking health (attempt $attempt/$max_attempts)..."
        health_response=$(curl -sk --max-time 5 https://127.0.0.1:8443/api/health/liveness 2>&1) || true

        if echo "$health_response" | grep -q '"status"'; then
            log_detail "Health endpoint: OK"
            echo "$health_response" | python3 -m json.tool 2>/dev/null | head -10 | while read line; do
                echo -e "    $line"
            done
            return 0
        fi

        if [[ $attempt -lt $max_attempts ]]; then
            sleep 2
        fi
        attempt=$((attempt + 1))
    done

    log_warn "Health endpoint not responding after $max_attempts attempts"
    log_detail "Last response: $health_response"
}

# Summary
show_summary() {
    local script_end=$(date +%s)
    local duration=$((script_end - SCRIPT_START))

    echo ""
    echo -e "${GREEN}${BOLD}=========================================="
    echo "  Update Complete!"
    echo "==========================================${NC}"
    echo ""
    log_detail "Total time: ${duration}s"
    log_detail "Commit: $(cd $APP_DIR && git log -1 --pretty=format:'%h (%s)')"
    log_detail "Service: $(sudo systemctl is-active $SERVICE_NAME)"
}

# Main execution
main() {
    echo -e "${BOLD}=========================================="
    echo "  HM1K Server Update"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "==========================================${NC}"

    check_permissions
    stop_service
    update_code
    update_dependencies
    build_agent_wheel
    sync_service_file
    start_service
    show_status
    health_check
    show_summary
}

main "$@"
