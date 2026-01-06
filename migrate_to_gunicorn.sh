#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Hash Master 1000 - Flask to Gunicorn Migration Script
# ============================================================================
# This script migrates a production HM1K deployment from Flask dev server
# to Gunicorn WSGI server for proper multi-user concurrent access support.
# ============================================================================

SERVICE_NAME="hm1k"
REPO_DIR="/home/audit/HashMaster1000"
VENV_DIR="${REPO_DIR}/.venv"

# Detect Python version (require 3.10+)
if command -v python3.11 &> /dev/null; then
    PYTHON_VERSION="python3.11"
elif command -v python3.10 &> /dev/null; then
    PYTHON_VERSION="python3.10"
else
    PYTHON_VERSION="python3"
fi

echo "=========================================="
echo "Hash Master 1000 - Gunicorn Migration"
echo "=========================================="
echo
echo "This script will migrate your HM1K deployment from Flask dev server"
echo "to Gunicorn WSGI server for production multi-user support."
echo
echo "Configuration:"
echo "  Repository: ${REPO_DIR}"
echo "  Service: ${SERVICE_NAME}"
echo "  Virtual environment: ${VENV_DIR}"
echo

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "[!] Error: Do not run this script as root or with sudo"
    echo "    Run as the application user (e.g., 'audit')"
    exit 1
fi

# Check if repo directory exists
if [[ ! -d "${REPO_DIR}" ]]; then
    echo "[!] Error: Repository directory not found: ${REPO_DIR}"
    exit 1
fi

cd "${REPO_DIR}"

# Check if .env file exists
if [[ ! -f .env ]]; then
    echo "[!] Error: .env file not found in ${REPO_DIR}"
    exit 1
fi

# Check if service exists
if [[ ! -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
    echo "[!] Error: systemd service '${SERVICE_NAME}' not found"
    echo "    Expected service file: /etc/systemd/system/${SERVICE_NAME}.service"
    exit 1
fi

# Detect current deployment method
echo "[*] Detecting current deployment method..."
EXEC_START_LINE="$(sudo systemctl show -p ExecStart --value "${SERVICE_NAME}")"
# Extract the actual command from systemd's verbose format
# Example: { path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /home/audit/HashMaster1000/hm1k.py ; ... }
FIRST_CMD="$(echo "${EXEC_START_LINE}" | grep -oP 'path=\K[^\s;]+' || echo "${EXEC_START_LINE}")"

if [[ "${FIRST_CMD}" == *"gunicorn"* ]]; then
    echo "[!] This server is already using Gunicorn deployment"
    echo "    Current ExecStart: ${EXEC_START_LINE}"
    echo
    echo "If you need to update the configuration, edit:"
    echo "  - ${REPO_DIR}/gunicorn.conf.py"
    echo "  - /etc/systemd/system/${SERVICE_NAME}.service"
    echo
    echo "Then run:"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl restart ${SERVICE_NAME}"
    exit 0
fi

if [[ "${FIRST_CMD}" == *"python"* ]]; then
    echo "[✓] Detected Flask dev server deployment"
    echo "    Current ExecStart: ${EXEC_START_LINE}"
else
    echo "[!] Warning: Unknown deployment method"
    echo "    Current ExecStart: ${EXEC_START_LINE}"
fi
echo

# Confirm migration
echo "=========================================="
echo "MIGRATION CONFIRMATION"
echo "=========================================="
echo
echo "This migration will:"
echo "  1. Stop the ${SERVICE_NAME} service"
echo "  2. Create a Python virtual environment at ${VENV_DIR}"
echo "  3. Install all dependencies (Flask, Gunicorn, bcrypt, etc.)"
echo "  4. Backup current systemd service file"
echo "  5. Install new Gunicorn-based service file"
echo "  6. Start the service with Gunicorn (8 workers, 2 threads)"
echo "  7. Verify HIBP database initialization"
echo
echo "Estimated downtime: 2-5 minutes"
echo
read -p "Do you want to proceed? (yes/no): " CONFIRM

if [[ "${CONFIRM,,}" != "yes" ]]; then
    echo "[!] Migration cancelled by user"
    exit 0
fi
echo

# Stop service
echo "[*] Stopping ${SERVICE_NAME} service..."
sudo systemctl stop "${SERVICE_NAME}"
echo "[✓] Service stopped"
echo

# Create virtual environment
if [[ -d "${VENV_DIR}" ]]; then
    echo "[*] Virtual environment already exists at ${VENV_DIR}"
else
    echo "[*] Creating virtual environment at ${VENV_DIR}..."
    "${PYTHON_VERSION}" -m venv "${VENV_DIR}"
    echo "[✓] Virtual environment created"
fi
echo

# Activate virtual environment
source "${VENV_DIR}/bin/activate"

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip --quiet
echo "[✓] pip upgraded"
echo

# Install dependencies
echo "[*] Installing dependencies from requirements.txt..."
pip install --upgrade -r requirements.txt
echo "[✓] Dependencies installed"
echo

# Ensure Gunicorn is installed (may not install from requirements.txt on some systems)
echo "[*] Ensuring Gunicorn is installed in virtual environment..."
pip install gunicorn
echo "[✓] Gunicorn installed"
echo

# Verify critical dependencies
echo "[*] Verifying dependencies..."
python -c "import flask; print('[✓] Flask OK')"
python -c "import gunicorn; print('[✓] Gunicorn OK')"
python -c "import flask_limiter; print('[✓] Flask-Limiter OK')"
python -c "import flask_wtf; print('[✓] Flask-WTF OK')"
python -c "import requests; print('[✓] requests OK')"
python -c "import bcrypt; print('[✓] bcrypt OK')"
python -c "import cryptography; print('[✓] cryptography OK')"
echo

# Create logs directory
echo "[*] Creating logs directory..."
mkdir -p "${REPO_DIR}/logs"
echo "[✓] Logs directory ready"
echo

# Check for gunicorn.conf.py
if [[ ! -f "${REPO_DIR}/gunicorn.conf.py" ]]; then
    echo "[!] Error: gunicorn.conf.py not found in ${REPO_DIR}"
    echo "    This file is required for Gunicorn deployment"
    echo "    Please copy it from your development repository"
    echo ""
    echo "    Expected location: ${REPO_DIR}/gunicorn.conf.py"
    exit 1
fi
echo "[*] Found gunicorn.conf.py"
echo

# Backup current systemd service file
BACKUP_FILE="/tmp/${SERVICE_NAME}.service.backup.$(date +%Y%m%d_%H%M%S)"
echo "[*] Backing up current systemd service file..."
sudo cp "/etc/systemd/system/${SERVICE_NAME}.service" "${BACKUP_FILE}"
echo "[✓] Backup saved to: ${BACKUP_FILE}"
echo

# Detect current service user from existing service file
CURRENT_SERVICE_USER="$(sudo grep -E '^User=' "/etc/systemd/system/${SERVICE_NAME}.service" | cut -d'=' -f2 || echo "")"
CURRENT_SERVICE_GROUP="$(sudo grep -E '^Group=' "/etc/systemd/system/${SERVICE_NAME}.service" | cut -d'=' -f2 || echo "")"

# If no User/Group specified, service runs as root (which is not ideal)
if [[ -z "${CURRENT_SERVICE_USER}" ]]; then
    echo "[!] Warning: Current service has no User= directive (runs as root)"
    echo "    For security, the new service will run as a non-root user"
    echo
fi

# Use current user for new service (should match who owns the files)
CURRENT_USER="$(whoami)"
CURRENT_GROUP="$(id -gn)"

echo "[*] New service will run as User=${CURRENT_USER}, Group=${CURRENT_GROUP}"
echo

# Check file ownership - ensure current user owns the application files
echo "[*] Checking file ownership..."
REPO_OWNER="$(stat -c '%U' "${REPO_DIR}")"
if [[ "${REPO_OWNER}" != "${CURRENT_USER}" ]]; then
    echo "[!] Warning: Repository is owned by '${REPO_OWNER}', not '${CURRENT_USER}'"
    echo "    Fixing file ownership to allow service to run as ${CURRENT_USER}..."
    echo
    sudo chown -R "${CURRENT_USER}:${CURRENT_GROUP}" "${REPO_DIR}"
    echo "[✓] File ownership updated to ${CURRENT_USER}:${CURRENT_GROUP}"
    echo
else
    echo "[✓] File ownership is correct (${CURRENT_USER}:${CURRENT_GROUP})"
    echo
fi

# Create new systemd service file
echo "[*] Creating new Gunicorn-based systemd service file..."
cat > "/tmp/${SERVICE_NAME}.service.new" <<EOF
[Unit]
Description=Hash Master 1000 - Password Audit Analysis Tool
After=network.target

[Service]
Type=notify
User=${CURRENT_USER}
Group=${CURRENT_GROUP}
WorkingDirectory=${REPO_DIR}
Environment="PATH=${VENV_DIR}/bin"
ExecStart=${VENV_DIR}/bin/gunicorn -c gunicorn.conf.py hm1k:app
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hm1k

[Install]
WantedBy=multi-user.target
EOF

# Install new service file
sudo cp "/tmp/${SERVICE_NAME}.service.new" "/etc/systemd/system/${SERVICE_NAME}.service"
rm "/tmp/${SERVICE_NAME}.service.new"
echo "[✓] New service file installed"
echo

# Reload systemd
echo "[*] Reloading systemd daemon..."
sudo systemctl daemon-reload
echo "[✓] systemd reloaded"
echo

# Start service
echo "[*] Starting ${SERVICE_NAME} service with Gunicorn..."
sudo systemctl start "${SERVICE_NAME}"
echo "[✓] Service started"
echo

# Wait for service to initialize
echo "[*] Waiting for service initialization (10 seconds)..."
sleep 10
echo

# Check service status
echo "=========================================="
echo "SERVICE STATUS"
echo "=========================================="
sudo systemctl --no-pager --lines=15 status "${SERVICE_NAME}" || true
echo

# Check HIBP database initialization
echo "=========================================="
echo "HIBP DATABASE INITIALIZATION"
echo "=========================================="
if grep -q "HIBP_LOCAL_DB_PATH" .env 2>/dev/null; then
    echo "[*] Checking HIBP database initialization in Gunicorn workers..."
    echo
    HIBP_LINES=$(sudo journalctl -u "${SERVICE_NAME}" --since "30 seconds ago" --no-pager | grep "HM1K.*HIBP" || echo "")

    if [[ -n "${HIBP_LINES}" ]]; then
        echo "${HIBP_LINES}"
        echo

        # Count how many workers loaded the database
        WORKER_COUNT=$(echo "${HIBP_LINES}" | grep "Local HIBP database ready" | wc -l)
        echo "[✓] HIBP database loaded in ${WORKER_COUNT} worker(s)"
    else
        echo "[!] Warning: No HIBP initialization messages found in logs"
        echo "    This may indicate the database is not configured or failed to load"
        echo
        echo "    To troubleshoot:"
        echo "      - Check logs: tail -f ${REPO_DIR}/logs/gunicorn_error.log"
        echo "      - Verify HIBP_LOCAL_DB_PATH in .env points to valid file"
        echo "      - Check file permissions on HIBP database file"
    fi
else
    echo "[i] HIBP_LOCAL_DB_PATH not set in .env - local database not configured"
fi
echo

# Migration complete
echo "=========================================="
echo "MIGRATION COMPLETE"
echo "=========================================="
echo
echo "[✓] Successfully migrated from Flask dev server to Gunicorn"
echo
echo "Security improvements:"
echo "  - Service now runs as ${CURRENT_USER} (not root)"
echo "  - Application files owned by ${CURRENT_USER}:${CURRENT_GROUP}"
echo "  - Follows principle of least privilege"
echo
echo "Configuration:"
echo "  - Workers: 8 (configurable in gunicorn.conf.py)"
echo "  - Threads per worker: 2"
echo "  - Total concurrent capacity: 16 requests"
echo "  - Timeout: 900s (15 minutes for long AAIA analyses)"
echo
echo "Service management:"
echo "  - Status:  sudo systemctl status ${SERVICE_NAME}"
echo "  - Restart: sudo systemctl restart ${SERVICE_NAME}"
echo "  - Stop:    sudo systemctl stop ${SERVICE_NAME}"
echo "  - Logs:    sudo journalctl -u ${SERVICE_NAME} -f"
echo
echo "Application logs:"
echo "  - Access:  tail -f ${REPO_DIR}/logs/gunicorn_access.log"
echo "  - Errors:  tail -f ${REPO_DIR}/logs/gunicorn_error.log"
echo
echo "Backup of old service file:"
echo "  ${BACKUP_FILE}"
echo
echo "To adjust worker count or timeout, edit:"
echo "  ${REPO_DIR}/gunicorn.conf.py"
echo
echo "Then reload:"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl restart ${SERVICE_NAME}"
echo
