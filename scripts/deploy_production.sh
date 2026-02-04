#!/bin/bash
#
# Hash Master 1000 - Production Deployment Script
#
# This script deploys HM1K as a production service with:
# - Dedicated service user
# - Gunicorn WSGI server with worker tuning
# - Nginx reverse proxy with SSL
# - systemd service management
# - Hashcat installation with multi-version support
# - Common wordlists and rules
#
# Designed to work on:
# - Fresh Ubuntu 24.04 LTS installations
# - Older Ubuntu/Debian systems (18.04+)
# - Systems with broken/missing packages
#
# Usage:
#   sudo ./deploy_production.sh [options]
#
# Options:
#   --hm1k-only        Only deploy HM1K (skip hashcat)
#   --hashcat-only     Only install hashcat (skip HM1K deployment)
#   --skip-wordlists   Skip downloading wordlists
#   --help             Show this help message
#
# Requirements:
#   - Ubuntu 18.04+ or Debian 10+
#   - Root/sudo access
#   - Git repository cloned or files copied to server
#

# Don't exit on error - we handle errors ourselves
set +e

# =============================================================================
# Configuration
# =============================================================================

# Paths
HM1K_HOME="/opt/hm1k"
HM1K_USER="hm1k"
HM1K_GROUP="hm1k"
VENV_PATH="${HM1K_HOME}/.venv"
LOG_DIR="/var/log/hm1k"
DATA_DIR="${HM1K_HOME}/data"

# Hashcat paths
HASHCAT_HOME="/opt/hashcat"
WORDLISTS_DIR="/opt/wordlists"
RULES_DIR="/opt/rules"

# Nginx/SSL
SSL_CERT_DIR="/etc/ssl/certs"
SSL_KEY_DIR="/etc/ssl/private"
NGINX_SITE="hm1k"

# Gunicorn tuning (adjust based on CPU cores)
GUNICORN_WORKERS=4        # (2 x cores) + 1 for CPU-bound; fewer for memory constraints
GUNICORN_THREADS=2        # Threads per worker for I/O-bound operations
GUNICORN_TIMEOUT=300      # 5 minutes for large file processing
GUNICORN_BIND="127.0.0.1:8000"

# Minimum Python version required
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track errors for summary
declare -a ERRORS=()
declare -a WARNINGS=()

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNINGS+=("$1")
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ERRORS+=("$1")
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
        OS_NAME="Unknown Linux"
    fi

    log_info "Detected OS: ${OS_NAME}"

    # Check if supported
    case "$OS_ID" in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            ;;
        rhel|centos|fedora|rocky|almalinux)
            PKG_MANAGER="dnf"
            if ! command -v dnf &>/dev/null; then
                PKG_MANAGER="yum"
            fi
            log_warn "RHEL-based systems have limited testing. Some steps may need manual adjustment."
            ;;
        *)
            log_warn "Unsupported OS: $OS_ID. Attempting apt-get..."
            PKG_MANAGER="apt-get"
            ;;
    esac
}

detect_cpu_info() {
    CPU_CORES=$(nproc 2>/dev/null || echo 2)
    CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "Unknown")

    # Calculate optimal workers: (2 x cores) + 1, but cap at 17
    OPTIMAL_WORKERS=$(( (CPU_CORES * 2) + 1 ))
    if [[ $OPTIMAL_WORKERS -gt 17 ]]; then
        OPTIMAL_WORKERS=17
    fi

    log_info "Detected CPU: ${CPU_MODEL}"
    log_info "CPU Cores: ${CPU_CORES}"
    log_info "Recommended Gunicorn workers: ${OPTIMAL_WORKERS}"

    GUNICORN_WORKERS=$OPTIMAL_WORKERS
}

# =============================================================================
# Package Management - Handle Broken Systems
# =============================================================================

fix_broken_packages() {
    log_info "Checking for broken packages..."

    # Fix dpkg interruptions
    if [[ -f /var/lib/dpkg/lock-frontend ]]; then
        # Check if dpkg is actually running
        if ! fuser /var/lib/dpkg/lock-frontend &>/dev/null; then
            log_info "Removing stale dpkg lock..."
            rm -f /var/lib/dpkg/lock-frontend
            rm -f /var/lib/dpkg/lock
            rm -f /var/cache/apt/archives/lock
        fi
    fi

    # Configure any unconfigured packages
    dpkg --configure -a 2>/dev/null || true

    # Fix broken dependencies
    apt-get install -f -y 2>/dev/null || true

    # Clean package cache
    apt-get clean 2>/dev/null || true
    apt-get autoclean 2>/dev/null || true

    log_success "Package system checked"
}

update_package_lists() {
    log_info "Updating package lists..."

    # Try to update, but don't fail if some repos are unavailable
    if ! apt-get update 2>&1 | tee /tmp/apt_update.log; then
        if grep -q "Failed to fetch" /tmp/apt_update.log; then
            log_warn "Some package repositories failed to update. Continuing with available repos..."
        fi
    fi

    rm -f /tmp/apt_update.log
    log_success "Package lists updated"
}

# =============================================================================
# Python Version Management
# =============================================================================

get_python_version() {
    local python_cmd="$1"
    if command -v "$python_cmd" &>/dev/null; then
        "$python_cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null
    fi
}

check_python_version() {
    log_info "Checking Python version..."

    # Try python3 first
    PYTHON_CMD=""
    PYTHON_VERSION=""

    for cmd in python3 python3.12 python3.11 python3.10; do
        if command -v "$cmd" &>/dev/null; then
            version=$(get_python_version "$cmd")
            if [[ -n "$version" ]]; then
                major=$(echo "$version" | cut -d. -f1)
                minor=$(echo "$version" | cut -d. -f2)

                if [[ "$major" -ge "$MIN_PYTHON_MAJOR" ]] && [[ "$minor" -ge "$MIN_PYTHON_MINOR" ]]; then
                    PYTHON_CMD="$cmd"
                    PYTHON_VERSION="$version"
                    break
                fi
            fi
        fi
    done

    if [[ -z "$PYTHON_CMD" ]]; then
        log_warn "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ not found. Will attempt to install..."
        return 1
    fi

    log_success "Found Python ${PYTHON_VERSION} at $(which $PYTHON_CMD)"
    return 0
}

install_python() {
    log_info "Installing Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+..."

    case "$OS_ID" in
        ubuntu)
            # Add deadsnakes PPA for newer Python on older Ubuntu
            if [[ "${OS_VERSION%%.*}" -lt 22 ]]; then
                log_info "Adding deadsnakes PPA for newer Python..."
                apt-get install -y software-properties-common 2>/dev/null || true
                add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
                apt-get update
            fi

            # Try to install Python 3.12, then 3.11, then 3.10
            for pyver in python3.12 python3.11 python3.10; do
                if apt-get install -y "$pyver" "${pyver}-venv" "${pyver}-dev" 2>/dev/null; then
                    PYTHON_CMD="$pyver"
                    PYTHON_VERSION=$(get_python_version "$pyver")
                    log_success "Installed $pyver"
                    break
                fi
            done
            ;;
        debian)
            # Debian usually has recent Python in backports
            apt-get install -y python3 python3-venv python3-dev 2>/dev/null || true
            ;;
        *)
            apt-get install -y python3 python3-venv python3-dev 2>/dev/null || true
            ;;
    esac

    # Verify installation
    if ! check_python_version; then
        log_error "Failed to install Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+. Please install manually."
        log_error "On Ubuntu: sudo apt install python3.11 python3.11-venv python3.11-dev"
        return 1
    fi

    return 0
}

# =============================================================================
# System Preparation
# =============================================================================

install_system_dependencies() {
    log_info "Installing system dependencies..."

    # Core packages - install in groups to handle failures better
    local core_packages=(
        python3-pip
        python3-venv
        python3-dev
        build-essential
        git
        curl
        wget
        openssl
        libssl-dev
        libffi-dev
    )

    local web_packages=(
        nginx
    )

    local optional_packages=(
        libcurl4-openssl-dev
        zlib1g-dev
        p7zip-full
        unzip
        rsync
    )

    # Install core packages
    log_info "Installing core packages..."
    for pkg in "${core_packages[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            apt-get install -y "$pkg" 2>/dev/null || log_warn "Could not install: $pkg"
        fi
    done

    # Install web packages
    log_info "Installing web server..."
    for pkg in "${web_packages[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            apt-get install -y "$pkg" 2>/dev/null || log_warn "Could not install: $pkg"
        fi
    done

    # Install optional packages (don't fail if unavailable)
    log_info "Installing optional packages..."
    for pkg in "${optional_packages[@]}"; do
        apt-get install -y "$pkg" 2>/dev/null || true
    done

    log_success "System dependencies installed"
}

# =============================================================================
# HM1K User & Directory Setup
# =============================================================================

setup_hm1k_user() {
    log_info "Setting up HM1K service user..."

    # Create service user if it doesn't exist
    if ! id -u "$HM1K_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$HM1K_HOME" "$HM1K_USER"
        log_success "Created user: $HM1K_USER"
    else
        log_info "User $HM1K_USER already exists"
    fi
}

setup_directories() {
    log_info "Setting up directories..."

    # Create HM1K directories
    mkdir -p "$HM1K_HOME"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "${DATA_DIR}/sessions"
    mkdir -p "${DATA_DIR}/uploads"
    mkdir -p "${HM1K_HOME}/flask_session"

    # Create hashcat directories
    mkdir -p "$HASHCAT_HOME"
    mkdir -p "${HASHCAT_HOME}/versions"
    mkdir -p "$WORDLISTS_DIR"
    mkdir -p "$RULES_DIR"

    log_success "Directories created"
}

# =============================================================================
# HM1K Application Setup
# =============================================================================

deploy_hm1k_files() {
    log_info "Deploying HM1K application files..."

    # Check if we're running from the repo directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_DIR="$(dirname "$SCRIPT_DIR")"

    if [[ -f "${REPO_DIR}/hm1k.py" ]]; then
        log_info "Copying files from repository at: $REPO_DIR"

        # Check for rsync
        if command -v rsync &>/dev/null; then
            rsync -av --exclude='.git' \
                      --exclude='.venv' \
                      --exclude='__pycache__' \
                      --exclude='*.pyc' \
                      --exclude='.env' \
                      --exclude='cert.pem' \
                      --exclude='key.pem' \
                      --exclude='data/sessions/*' \
                      --exclude='testData' \
                      --exclude='internal' \
                      "$REPO_DIR/" "$HM1K_HOME/"
        else
            # Fallback to cp if rsync not available
            log_warn "rsync not available, using cp (may copy unwanted files)"
            cp -r "$REPO_DIR"/* "$HM1K_HOME/"
            # Clean up unwanted files
            rm -rf "${HM1K_HOME}/.git"
            rm -rf "${HM1K_HOME}/.venv"
            rm -rf "${HM1K_HOME}/__pycache__"
            rm -f "${HM1K_HOME}/.env"
            rm -rf "${HM1K_HOME}/testData"
            rm -rf "${HM1K_HOME}/internal"
        fi
    else
        log_error "Cannot find HM1K repository. Run this script from the repo or copy files manually to $HM1K_HOME"
        return 1
    fi

    log_success "Application files deployed"
}

setup_python_environment() {
    log_info "Setting up Python virtual environment..."

    # Determine Python command to use
    local python_to_use="${PYTHON_CMD:-python3}"

    # Create venv
    if ! "$python_to_use" -m venv "$VENV_PATH" 2>/dev/null; then
        # Try with --without-pip if venv module has issues
        log_warn "Standard venv creation failed, trying alternative..."
        "$python_to_use" -m venv --without-pip "$VENV_PATH"

        # Install pip manually
        curl -sS https://bootstrap.pypa.io/get-pip.py | "$VENV_PATH/bin/python"
    fi

    # Upgrade pip
    "$VENV_PATH/bin/pip" install --upgrade pip wheel setuptools 2>/dev/null || true

    # Install requirements
    if [[ -f "${HM1K_HOME}/requirements.txt" ]]; then
        log_info "Installing Python requirements..."
        if ! "$VENV_PATH/bin/pip" install -r "${HM1K_HOME}/requirements.txt"; then
            log_error "Failed to install some Python requirements"
            # Try installing one by one to identify problem packages
            while IFS= read -r requirement; do
                # Skip comments and empty lines
                [[ "$requirement" =~ ^#.*$ ]] && continue
                [[ -z "$requirement" ]] && continue
                "$VENV_PATH/bin/pip" install "$requirement" 2>/dev/null || log_warn "Could not install: $requirement"
            done < "${HM1K_HOME}/requirements.txt"
        fi
    else
        log_error "requirements.txt not found at ${HM1K_HOME}/requirements.txt"
    fi

    # Install Gunicorn for production
    "$VENV_PATH/bin/pip" install gunicorn

    # Ensure flask-compress is installed (common missing dependency)
    "$VENV_PATH/bin/pip" install flask-compress 2>/dev/null || true

    log_success "Python environment configured"
}

download_nltk_data() {
    log_info "Downloading NLTK data..."

    # Download NLTK data needed by HM1K
    "$VENV_PATH/bin/python" -c "
import nltk
import os

# Set download directory
nltk_data_dir = '/usr/share/nltk_data'
os.makedirs(nltk_data_dir, exist_ok=True)

# Download required datasets
datasets = ['words', 'names', 'averaged_perceptron_tagger', 'punkt']
for dataset in datasets:
    try:
        nltk.download(dataset, download_dir=nltk_data_dir, quiet=True)
        print(f'Downloaded: {dataset}')
    except Exception as e:
        print(f'Warning: Could not download {dataset}: {e}')
" 2>/dev/null || log_warn "Could not download some NLTK data. This may affect some features."

    log_success "NLTK data downloaded"
}

configure_hm1k_env() {
    log_info "Configuring HM1K environment..."

    ENV_FILE="${HM1K_HOME}/.env"

    # Generate secure secret key
    SECRET_KEY=$("$VENV_PATH/bin/python" -c 'import secrets; print(secrets.token_hex(32))' 2>/dev/null || openssl rand -hex 32)

    if [[ ! -f "$ENV_FILE" ]]; then
        cat > "$ENV_FILE" << EOF
# Hash Master 1000 Production Configuration
# Generated on $(date)

# Security - CHANGE THESE!
SECRET_KEY="${SECRET_KEY}"
ADMIN_USERNAME="admin"
# Default password: Winter2026## (change this!)
ADMIN_PASSWORD_HASH="\$2b\$12\$PzAkEQKfwFcafUK2RH08zO9Os3YFz7rq.4UqwaLHlFONDlqxncmnO"

# Multi-user mode (optional)
# MULTI_USER_MODE="true"

# Session settings
SESSION_LIFETIME=86400

# File paths (optional - for convenience)
# DEFAULT_PWDUMP_PATH="/path/to/hashes.ntds"
# DEFAULT_POTFILE_PATH="/path/to/hashcat.potfile"
# DEFAULT_ADD_JSON_PATH="/path/to/domain.json"

# HIBP local database (if downloaded)
# HIBP_LOCAL_DB="${DATA_DIR}/hibp_ntlm.db"

# Ollama AI Integration (optional)
# OLLAMA_ENABLED="true"
# OLLAMA_HOST="http://localhost:11434"
# OLLAMA_TIMEOUT="120"
# AI_PIPELINE_DEBUG="false"

# Advanced options (off by default)
ADVANCED_OPTIONS_ENABLED="false"
EOF
        log_success "Created .env file with secure secret key"
    else
        log_info ".env file already exists, skipping"
    fi
}

set_permissions() {
    log_info "Setting file permissions..."

    # Set ownership
    chown -R "$HM1K_USER:$HM1K_GROUP" "$HM1K_HOME"
    chown -R "$HM1K_USER:$HM1K_GROUP" "$LOG_DIR"

    # Protect sensitive files
    chmod 600 "${HM1K_HOME}/.env" 2>/dev/null || true
    chmod 700 "$DATA_DIR"
    chmod 700 "${HM1K_HOME}/flask_session"

    log_success "Permissions configured"
}

# =============================================================================
# SSL Certificate Generation
# =============================================================================

generate_ssl_certificate() {
    log_info "Generating self-signed SSL certificate..."

    CERT_FILE="${SSL_CERT_DIR}/hm1k.crt"
    KEY_FILE="${SSL_KEY_DIR}/hm1k.key"

    if [[ -f "$CERT_FILE" ]] && [[ -f "$KEY_FILE" ]]; then
        log_info "SSL certificate already exists"
        return
    fi

    # Generate certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=Security/CN=hm1k.local" 2>/dev/null

    if [[ $? -eq 0 ]]; then
        chmod 600 "$KEY_FILE"
        log_success "SSL certificate generated"
        log_warn "This is a self-signed certificate. Replace with a proper cert for production."
    else
        log_error "Failed to generate SSL certificate"
    fi
}

# =============================================================================
# Systemd Service Setup
# =============================================================================

create_systemd_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/hm1k.service << EOF
[Unit]
Description=Hash Master 1000 - Password Audit Tool
Documentation=https://github.com/shellntel/hm1k
After=network.target

[Service]
Type=notify
User=${HM1K_USER}
Group=${HM1K_GROUP}
WorkingDirectory=${HM1K_HOME}
Environment="PATH=${VENV_PATH}/bin"
Environment="PYTHONUNBUFFERED=1"

# Gunicorn command
ExecStart=${VENV_PATH}/bin/gunicorn \\
    --workers ${GUNICORN_WORKERS} \\
    --threads ${GUNICORN_THREADS} \\
    --worker-class gthread \\
    --bind ${GUNICORN_BIND} \\
    --timeout ${GUNICORN_TIMEOUT} \\
    --access-logfile ${LOG_DIR}/access.log \\
    --error-logfile ${LOG_DIR}/error.log \\
    --capture-output \\
    --enable-stdio-inheritance \\
    hm1k:app

# Restart policy
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${HM1K_HOME}/data ${LOG_DIR} ${HM1K_HOME}/flask_session

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    log_success "Systemd service created"
}

# =============================================================================
# Nginx Configuration
# =============================================================================

configure_nginx() {
    log_info "Configuring Nginx..."

    cat > /etc/nginx/sites-available/${NGINX_SITE} << 'EOF'
# Hash Master 1000 - Nginx Configuration

# Rate limiting zone
limit_req_zone $binary_remote_addr zone=hm1k_limit:10m rate=10r/s;

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/hm1k.crt;
    ssl_certificate_key /etc/ssl/private/hm1k.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # File upload limit (for large pwdump files)
    client_max_body_size 500M;
    client_body_timeout 300s;

    # Proxy timeouts (for long-running operations)
    proxy_connect_timeout 60s;
    proxy_send_timeout 300s;
    proxy_read_timeout 300s;

    # Static files - served directly by Nginx
    location /static/ {
        alias /opt/hm1k/static/;
        expires 7d;
        add_header Cache-Control "public, immutable";

        # Gzip static files
        gzip_static on;
    }

    # Favicon
    location /favicon.ico {
        alias /opt/hm1k/static/images/favicon.ico;
        expires 30d;
    }

    # Application proxy
    location / {
        # Rate limiting
        limit_req zone=hm1k_limit burst=20 nodelay;

        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;

        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # WebSocket support (if needed)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
        access_log off;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 301 https://$host$request_uri;
}
EOF

    # Enable site
    ln -sf /etc/nginx/sites-available/${NGINX_SITE} /etc/nginx/sites-enabled/

    # Remove default site if exists
    rm -f /etc/nginx/sites-enabled/default

    # Test configuration
    if nginx -t 2>/dev/null; then
        log_success "Nginx configured"
    else
        log_error "Nginx configuration test failed. Check: nginx -t"
    fi
}

# =============================================================================
# Hashcat Installation
# =============================================================================

install_hashcat_dependencies() {
    log_info "Installing hashcat dependencies..."

    apt-get install -y \
        build-essential \
        git \
        libcurl4-openssl-dev \
        libssl-dev \
        zlib1g-dev \
        ocl-icd-opencl-dev \
        opencl-headers \
        pocl-opencl-icd \
        clinfo 2>/dev/null || true

    log_success "Hashcat dependencies installed"
}

install_hashcat_version() {
    local VERSION="$1"
    local INSTALL_DIR="${HASHCAT_HOME}/versions/${VERSION}"

    log_info "Installing hashcat ${VERSION}..."

    if [[ -d "$INSTALL_DIR" ]]; then
        log_info "Hashcat ${VERSION} already installed at ${INSTALL_DIR}"
        return
    fi

    mkdir -p "$INSTALL_DIR"
    cd /tmp

    # Clone and build
    rm -rf "hashcat-${VERSION}"
    git clone --branch "v${VERSION}" --depth 1 https://github.com/hashcat/hashcat.git "hashcat-${VERSION}" 2>/dev/null || \
    git clone --branch "${VERSION}" --depth 1 https://github.com/hashcat/hashcat.git "hashcat-${VERSION}"

    if [[ $? -ne 0 ]]; then
        log_warn "Could not clone hashcat ${VERSION}"
        return
    fi

    cd "hashcat-${VERSION}"
    make -j$(nproc)

    # Copy to install directory
    cp -r hashcat *.bin charsets layouts masks modules OpenCL rules "$INSTALL_DIR/" 2>/dev/null || true
    cp hashcat "$INSTALL_DIR/"

    # Create version-specific symlink
    ln -sf "${INSTALL_DIR}/hashcat" "/usr/local/bin/hashcat-${VERSION}"

    # Cleanup
    cd /tmp
    rm -rf "hashcat-${VERSION}"

    log_success "Hashcat ${VERSION} installed to ${INSTALL_DIR}"
}

install_hashcat_latest() {
    log_info "Installing latest hashcat from apt (as default)..."

    apt-get install -y hashcat 2>/dev/null

    # Get version
    INSTALLED_VERSION=$(hashcat --version 2>/dev/null | head -1 || echo "unknown")
    log_success "Installed hashcat from apt: ${INSTALLED_VERSION}"
}

install_hashcat_utils() {
    log_info "Installing hashcat-utils..."

    cd /tmp
    rm -rf hashcat-utils
    git clone --depth 1 https://github.com/hashcat/hashcat-utils.git 2>/dev/null

    if [[ ! -d hashcat-utils ]]; then
        log_warn "Could not clone hashcat-utils"
        return
    fi

    cd hashcat-utils

    # Check if Makefile works, otherwise build individual tools
    if make -C src 2>/dev/null; then
        cp src/*.bin /usr/local/bin/ 2>/dev/null || true
    else
        log_info "Makefile failed, building individual tools..."
        cd src
        # Build each C file individually
        for f in *.c; do
            name="${f%.c}"
            if gcc -O2 -o "${name}.bin" "$f" -lcrypto 2>/dev/null || \
               gcc -O2 -o "${name}.bin" "$f" 2>/dev/null; then
                log_info "  Built: ${name}"
            fi
        done
        cp *.bin /usr/local/bin/ 2>/dev/null || true
    fi

    # Create symlinks without .bin extension
    cd /usr/local/bin
    for bin in *.bin 2>/dev/null; do
        [[ -f "$bin" ]] && ln -sf "$bin" "${bin%.bin}"
    done

    # Cleanup
    cd /tmp
    rm -rf hashcat-utils

    log_success "hashcat-utils installed"
}

setup_hashcat_symlinks() {
    log_info "Setting up hashcat version management..."

    # Create management script
    cat > /usr/local/bin/hashcat-switch << 'EOF'
#!/bin/bash
# Switch active hashcat version
#
# Usage: hashcat-switch <version>
# Example: hashcat-switch 6.2.6

HASHCAT_HOME="/opt/hashcat"
VERSION="$1"

if [[ -z "$VERSION" ]]; then
    echo "Available hashcat versions:"
    ls -1 "${HASHCAT_HOME}/versions/" 2>/dev/null || echo "No versions installed"
    echo ""
    echo "System hashcat: $(which hashcat) - $(hashcat --version 2>/dev/null || echo 'not installed')"
    echo ""
    echo "Usage: hashcat-switch <version>"
    exit 0
fi

VERSION_DIR="${HASHCAT_HOME}/versions/${VERSION}"

if [[ ! -d "$VERSION_DIR" ]]; then
    echo "Error: Version ${VERSION} not found in ${HASHCAT_HOME}/versions/"
    echo "Available versions:"
    ls -1 "${HASHCAT_HOME}/versions/"
    exit 1
fi

# Update default symlink
ln -sf "${VERSION_DIR}/hashcat" /usr/local/bin/hashcat

echo "Switched to hashcat ${VERSION}"
hashcat --version
EOF
    chmod +x /usr/local/bin/hashcat-switch

    # Create benchmark script
    cat > /usr/local/bin/hashcat-benchmark-all << 'EOF'
#!/bin/bash
# Benchmark all installed hashcat versions
#
# Usage: hashcat-benchmark-all [hash_mode]
# Default hash mode: 1000 (NTLM)

HASHCAT_HOME="/opt/hashcat"
HASH_MODE="${1:-1000}"
OUTPUT_FILE="/tmp/hashcat_benchmark_$(date +%Y%m%d_%H%M%S).txt"

echo "Hashcat Multi-Version Benchmark"
echo "Hash Mode: ${HASH_MODE}"
echo "Output: ${OUTPUT_FILE}"
echo "================================"
echo ""

{
    echo "Hashcat Multi-Version Benchmark"
    echo "Date: $(date)"
    echo "Hash Mode: ${HASH_MODE}"
    echo "System: $(uname -a)"
    echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    echo ""
    echo "================================"

    # System hashcat first
    if command -v hashcat &>/dev/null && [[ "$(readlink -f $(which hashcat))" == "/usr/bin/hashcat" ]]; then
        echo ""
        echo "=== System hashcat (apt) ==="
        hashcat --version
        hashcat -b -m "$HASH_MODE" --force 2>&1 || true
    fi

    # Test each installed version
    for VERSION_DIR in "${HASHCAT_HOME}/versions/"*/; do
        if [[ -d "$VERSION_DIR" ]]; then
            VERSION=$(basename "$VERSION_DIR")
            echo ""
            echo "=== Hashcat ${VERSION} ==="
            "${VERSION_DIR}/hashcat" --version 2>&1 || true
            "${VERSION_DIR}/hashcat" -b -m "$HASH_MODE" --force 2>&1 || true
        fi
    done

    echo ""
    echo "================================"
    echo "Benchmark complete: $(date)"

} | tee "$OUTPUT_FILE"

echo ""
echo "Results saved to: ${OUTPUT_FILE}"
EOF
    chmod +x /usr/local/bin/hashcat-benchmark-all

    log_success "Hashcat management scripts created"
}

# =============================================================================
# Wordlists & Rules
# =============================================================================

download_wordlists() {
    log_info "Downloading wordlists..."

    cd "$WORDLISTS_DIR"

    # RockYou
    if [[ ! -f "rockyou.txt" ]]; then
        log_info "Downloading RockYou..."
        wget -q --show-progress -O rockyou.txt.gz \
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" 2>/dev/null || \
        wget -q --show-progress -O rockyou.txt.gz \
            "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz" || true

        if [[ -f "rockyou.txt.gz" ]]; then
            gunzip -f rockyou.txt.gz 2>/dev/null || mv rockyou.txt.gz rockyou.txt
        fi
    fi

    # Weakpass collection (smaller curated lists)
    if [[ ! -f "weakpass_2a.txt" ]]; then
        log_info "Downloading Weakpass 2a (~100MB)..."
        wget -q --show-progress -O weakpass_2a.txt.gz \
            "https://weakpass.com/download/1851" 2>/dev/null && \
        gunzip -f weakpass_2a.txt.gz || true
    fi

    # SecLists (if not too large)
    if [[ ! -d "SecLists" ]]; then
        log_info "Cloning SecLists password lists..."
        git clone --depth 1 --filter=blob:none --sparse \
            https://github.com/danielmiessler/SecLists.git 2>/dev/null
        if [[ -d "SecLists" ]]; then
            cd SecLists
            git sparse-checkout set Passwords 2>/dev/null || true
            cd ..
        fi
    fi

    # Create index
    log_info "Creating wordlist index..."
    cat > "${WORDLISTS_DIR}/README.txt" << EOF
Wordlist Directory Index
========================
Generated: $(date)

Files:
$(ls -lh *.txt 2>/dev/null || echo "No .txt files")

Directories:
$(ls -d */ 2>/dev/null || echo "No subdirectories")

Usage with hashcat:
  hashcat -m 1000 hashes.txt -a 0 ${WORDLISTS_DIR}/rockyou.txt
  hashcat -m 1000 hashes.txt -a 0 ${WORDLISTS_DIR}/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
EOF

    log_success "Wordlists downloaded to ${WORDLISTS_DIR}"
}

download_rules() {
    log_info "Downloading hashcat rules..."

    cd "$RULES_DIR"

    # OneRuleToRuleThemAll
    if [[ ! -f "OneRuleToRuleThemAll.rule" ]]; then
        wget -q --show-progress -O OneRuleToRuleThemAll.rule \
            "https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule" 2>/dev/null || true
    fi

    # Best64
    if [[ ! -f "best64.rule" ]]; then
        wget -q --show-progress -O best64.rule \
            "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/best64.rule" 2>/dev/null || true
    fi

    # d3ad0ne
    if [[ ! -f "d3ad0ne.rule" ]]; then
        wget -q --show-progress -O d3ad0ne.rule \
            "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/d3ad0ne.rule" 2>/dev/null || true
    fi

    # dive
    if [[ ! -f "dive.rule" ]]; then
        wget -q --show-progress -O dive.rule \
            "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/dive.rule" 2>/dev/null || true
    fi

    # Hob0Rules
    if [[ ! -f "hob064.rule" ]]; then
        wget -q --show-progress -O hob064.rule \
            "https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/hob064.rule" 2>/dev/null || true
    fi

    # Corporate rules (common password policies)
    if [[ ! -f "corporate.rule" ]]; then
        cat > corporate.rule << 'RULES'
# Corporate password rules - common mutations for policy compliance
# Append numbers
$1
$2
$!
$@
$#
$1$2$3
$1$2$3$4
# Capitalize first letter
c
# Append year patterns
$2$0$2$3
$2$0$2$4
$2$0$2$5
$2$0$2$6
# Common special char endings
$!
$@
$#
$$
$!$!
# Toggle case + append
c$1
c$!
c$1$!
c$1$2$3
c$1$2$3$!
# Season patterns
c$2$0$2$4
c$2$0$2$5
RULES
    fi

    log_success "Rules downloaded to ${RULES_DIR}"
}

# =============================================================================
# Service Management
# =============================================================================

start_services() {
    log_info "Starting services..."

    # Enable and start HM1K
    systemctl enable hm1k
    systemctl start hm1k

    # Reload and start Nginx
    systemctl enable nginx
    systemctl reload nginx || systemctl restart nginx

    # Check status
    sleep 3
    if systemctl is-active --quiet hm1k; then
        log_success "HM1K service is running"
    else
        log_error "HM1K service failed to start. Check: journalctl -u hm1k -n 50"
    fi

    if systemctl is-active --quiet nginx; then
        log_success "Nginx is running"
    else
        log_error "Nginx failed to start. Check: nginx -t"
    fi
}

# =============================================================================
# Admin Credential Setup
# =============================================================================

setup_admin_credentials() {
    echo ""
    echo "============================================"
    echo "       Admin Credential Setup"
    echo "============================================"
    echo ""
    echo "The default admin credentials are:"
    echo "  Username: admin"
    echo "  Password: Winter2026##"
    echo ""

    read -p "Would you like to set a custom admin username and password now? (y/N): " setup_creds

    if [[ "${setup_creds,,}" == "y" || "${setup_creds,,}" == "yes" ]]; then
        echo ""

        # Get username
        read -p "Enter admin username [admin]: " new_username
        new_username="${new_username:-admin}"

        # Get password (with confirmation)
        while true; do
            read -s -p "Enter admin password: " new_password
            echo ""

            if [[ -z "$new_password" ]]; then
                echo "Password cannot be empty. Please try again."
                continue
            fi

            if [[ ${#new_password} -lt 8 ]]; then
                echo "Password must be at least 8 characters. Please try again."
                continue
            fi

            read -s -p "Confirm admin password: " confirm_password
            echo ""

            if [[ "$new_password" != "$confirm_password" ]]; then
                echo "Passwords do not match. Please try again."
                continue
            fi

            break
        done

        # Generate bcrypt hash
        log_info "Generating password hash..."
        password_hash=$("$VENV_PATH/bin/python" -c "
import bcrypt
password = '''$new_password'''
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
print(hashed.decode('utf-8'))
" 2>/dev/null)

        if [[ -z "$password_hash" ]]; then
            log_error "Failed to generate password hash. Please update .env manually."
            return
        fi

        # Update .env file
        ENV_FILE="${HM1K_HOME}/.env"

        # Escape special characters for sed
        escaped_hash=$(printf '%s\n' "$password_hash" | sed 's/[&/\$]/\\&/g')

        # Update username and password hash
        sed -i "s/^ADMIN_USERNAME=.*/ADMIN_USERNAME=\"$new_username\"/" "$ENV_FILE"
        sed -i "s|^ADMIN_PASSWORD_HASH=.*|ADMIN_PASSWORD_HASH=\"$escaped_hash\"|" "$ENV_FILE"

        # Remove the default password comment
        sed -i '/# Default password: Winter2026##/d' "$ENV_FILE"

        log_success "Admin credentials updated!"
        echo ""
        echo "New admin credentials:"
        echo "  Username: $new_username"
        echo "  Password: ********** (as entered)"
        echo ""

        # Restart service to apply changes
        log_info "Restarting HM1K service to apply changes..."
        systemctl restart hm1k
        sleep 2

        if systemctl is-active --quiet hm1k; then
            log_success "HM1K service restarted successfully"
        else
            log_error "HM1K service failed to restart. Check: journalctl -u hm1k -n 50"
        fi
    else
        echo ""
        log_warn "Using default credentials. Please change them in ${HM1K_HOME}/.env"
        echo ""
        echo "To change credentials later, edit ${HM1K_HOME}/.env and run:"
        echo "  sudo systemctl restart hm1k"
    fi
}

# =============================================================================
# Verification
# =============================================================================

verify_installation() {
    log_info "Verifying installation..."

    echo ""
    echo "============================================"
    echo "       Installation Verification"
    echo "============================================"
    echo ""

    # HM1K
    echo "HM1K Service:"
    systemctl status hm1k --no-pager -l 2>/dev/null | head -10 || echo "  Service status unavailable"
    echo ""

    # Nginx
    echo "Nginx Status:"
    systemctl status nginx --no-pager 2>/dev/null | head -5 || echo "  Nginx status unavailable"
    echo ""

    # Test local connection
    echo "Testing local connection..."
    sleep 2
    if curl -sk https://localhost/ 2>/dev/null | grep -qi "hash\|master\|login"; then
        log_success "HM1K responding on https://localhost"
    elif curl -sk http://127.0.0.1:8000/ 2>/dev/null | grep -qi "hash\|master\|login"; then
        log_success "HM1K responding on http://127.0.0.1:8000 (direct)"
    else
        log_warn "Could not verify HM1K response (may still be starting)"
    fi
    echo ""

    # Hashcat
    echo "Hashcat versions:"
    echo "  System: $(hashcat --version 2>/dev/null || echo 'not installed')"
    for dir in "${HASHCAT_HOME}/versions/"*/; do
        if [[ -d "$dir" ]]; then
            VERSION=$(basename "$dir")
            echo "  ${VERSION}: $("${dir}/hashcat" --version 2>/dev/null || echo 'error')"
        fi
    done
    echo ""

    # OpenCL
    echo "OpenCL devices:"
    clinfo -l 2>/dev/null || echo "  (clinfo not available)"
    echo ""
}

print_summary() {
    echo ""
    echo "============================================"
    echo "       Installation Summary"
    echo "============================================"
    echo ""

    # Get IP address
    IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

    echo "HM1K URL:        https://${IP_ADDR}"
    echo "HM1K Home:       ${HM1K_HOME}"
    echo "HM1K Logs:       ${LOG_DIR}"
    echo "HM1K Config:     ${HM1K_HOME}/.env"
    echo ""
    echo "Hashcat Home:    ${HASHCAT_HOME}"
    echo "Wordlists:       ${WORDLISTS_DIR}"
    echo "Rules:           ${RULES_DIR}"
    echo ""
    echo "Commands:"
    echo "  hashcat-switch          - List/switch hashcat versions"
    echo "  hashcat-benchmark-all   - Benchmark all versions"
    echo "  systemctl status hm1k   - Check HM1K status"
    echo "  journalctl -u hm1k -f   - Follow HM1K logs"
    echo ""

    # Print errors if any
    if [[ ${#ERRORS[@]} -gt 0 ]]; then
        echo ""
        echo -e "${RED}============================================${NC}"
        echo -e "${RED}       Errors During Installation${NC}"
        echo -e "${RED}============================================${NC}"
        for err in "${ERRORS[@]}"; do
            echo -e "${RED}  - $err${NC}"
        done
        echo ""
    fi

    # Print warnings if any
    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}============================================${NC}"
        echo -e "${YELLOW}       Warnings During Installation${NC}"
        echo -e "${YELLOW}============================================${NC}"
        for warn in "${WARNINGS[@]}"; do
            echo -e "${YELLOW}  - $warn${NC}"
        done
        echo ""
    fi
}

# =============================================================================
# Main
# =============================================================================

print_usage() {
    echo "Hash Master 1000 - Production Deployment Script"
    echo ""
    echo "Usage: sudo $0 [options]"
    echo ""
    echo "Options:"
    echo "  --hm1k-only        Only deploy HM1K (skip hashcat)"
    echo "  --hashcat-only     Only install hashcat (skip HM1K deployment)"
    echo "  --skip-wordlists   Skip downloading wordlists"
    echo "  --hashcat-versions Comma-separated list of hashcat versions to install"
    echo "                     Example: --hashcat-versions 6.2.5,6.2.6"
    echo "  --help             Show this help message"
    echo ""
}

main() {
    local DEPLOY_HM1K=true
    local DEPLOY_HASHCAT=true
    local DOWNLOAD_WORDLISTS=true
    local HASHCAT_VERSIONS="6.2.6"  # Default version to build from source

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hm1k-only)
                DEPLOY_HASHCAT=false
                shift
                ;;
            --hashcat-only)
                DEPLOY_HM1K=false
                shift
                ;;
            --skip-wordlists)
                DOWNLOAD_WORDLISTS=false
                shift
                ;;
            --hashcat-versions)
                HASHCAT_VERSIONS="$2"
                shift 2
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done

    echo "============================================"
    echo "  Hash Master 1000 Production Deployment"
    echo "============================================"
    echo ""

    check_root
    detect_os
    detect_cpu_info

    # Fix any broken packages first
    fix_broken_packages
    update_package_lists

    # Check Python version
    if ! check_python_version; then
        install_python
    fi

    # System prep
    install_system_dependencies
    setup_directories

    # HM1K deployment
    if [[ "$DEPLOY_HM1K" == "true" ]]; then
        echo ""
        log_info "=== Deploying Hash Master 1000 ==="
        setup_hm1k_user
        deploy_hm1k_files
        setup_python_environment
        download_nltk_data
        configure_hm1k_env
        set_permissions
        generate_ssl_certificate
        create_systemd_service
        configure_nginx
    fi

    # Hashcat deployment
    if [[ "$DEPLOY_HASHCAT" == "true" ]]; then
        echo ""
        log_info "=== Installing Hashcat ==="
        install_hashcat_dependencies

        # Install from apt as default
        install_hashcat_latest

        # Install requested versions from source
        IFS=',' read -ra VERSIONS <<< "$HASHCAT_VERSIONS"
        for VERSION in "${VERSIONS[@]}"; do
            VERSION=$(echo "$VERSION" | xargs)  # Trim whitespace
            if [[ -n "$VERSION" ]]; then
                install_hashcat_version "$VERSION"
            fi
        done

        install_hashcat_utils
        setup_hashcat_symlinks

        if [[ "$DOWNLOAD_WORDLISTS" == "true" ]]; then
            echo ""
            log_info "=== Downloading Wordlists & Rules ==="
            download_wordlists
            download_rules
        fi
    fi

    # Start services
    if [[ "$DEPLOY_HM1K" == "true" ]]; then
        echo ""
        start_services
    fi

    # Verify
    echo ""
    verify_installation

    # Setup admin credentials interactively
    if [[ "$DEPLOY_HM1K" == "true" ]]; then
        setup_admin_credentials
    fi

    # Print summary
    print_summary

    if [[ ${#ERRORS[@]} -eq 0 ]]; then
        log_success "Deployment complete!"
    else
        log_warn "Deployment complete with ${#ERRORS[@]} error(s). Please review above."
    fi
}

main "$@"
