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
#   - Ubuntu 22.04+ or Debian 12+
#   - Root/sudo access
#   - Git repository cloned or files copied to server
#

set -e  # Exit on error

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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_cpu_info() {
    CPU_CORES=$(nproc)
    CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)

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
# System Preparation
# =============================================================================

install_system_dependencies() {
    log_info "Installing system dependencies..."

    apt-get update
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        git \
        curl \
        wget \
        nginx \
        openssl \
        libssl-dev \
        libffi-dev \
        libcurl4-openssl-dev \
        zlib1g-dev \
        p7zip-full \
        unzip

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

    # Create HM1K home if needed
    mkdir -p "$HM1K_HOME"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "${DATA_DIR}/sessions"
    mkdir -p "${DATA_DIR}/uploads"

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

        # Copy application files (excluding dev files)
        rsync -av --exclude='.git' \
                  --exclude='.venv' \
                  --exclude='__pycache__' \
                  --exclude='*.pyc' \
                  --exclude='.env' \
                  --exclude='cert.pem' \
                  --exclude='key.pem' \
                  --exclude='data/sessions/*' \
                  --exclude='testData' \
                  "$REPO_DIR/" "$HM1K_HOME/"
    else
        log_error "Cannot find HM1K repository. Run this script from the repo or copy files manually to $HM1K_HOME"
        exit 1
    fi

    log_success "Application files deployed"
}

setup_python_environment() {
    log_info "Setting up Python virtual environment..."

    # Create venv
    python3 -m venv "$VENV_PATH"

    # Upgrade pip
    "$VENV_PATH/bin/pip" install --upgrade pip wheel setuptools

    # Install requirements
    "$VENV_PATH/bin/pip" install -r "${HM1K_HOME}/requirements.txt"

    # Install Gunicorn for production
    "$VENV_PATH/bin/pip" install gunicorn

    log_success "Python environment configured"
}

configure_hm1k_env() {
    log_info "Configuring HM1K environment..."

    ENV_FILE="${HM1K_HOME}/.env"

    # Generate secure secret key
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

    if [[ ! -f "$ENV_FILE" ]]; then
        cat > "$ENV_FILE" << EOF
# Hash Master 1000 Production Configuration
# Generated on $(date)

# Security - CHANGE THESE!
SECRET_KEY="${SECRET_KEY}"
ADMIN_USERNAME="admin"
# Default password: Winter2025## (change this!)
ADMIN_PASSWORD_HASH="\$2b\$12\$eNKlXXTpqFIlXKEAvoUSaujC3MYUMnji4LDoftnnZMMRAwPMN.JkO"

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
        log_warn "IMPORTANT: Change the admin password in $ENV_FILE"
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
        -subj "/C=US/ST=State/L=City/O=Organization/OU=Security/CN=hm1k.local"

    chmod 600 "$KEY_FILE"

    log_success "SSL certificate generated"
    log_warn "This is a self-signed certificate. Replace with a proper cert for production."
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
ReadWritePaths=${HM1K_HOME}/data ${LOG_DIR}

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
    nginx -t

    log_success "Nginx configured"
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
        clinfo

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

    apt-get install -y hashcat

    # Get version
    INSTALLED_VERSION=$(hashcat --version 2>/dev/null | head -1 || echo "unknown")
    log_success "Installed hashcat from apt: ${INSTALLED_VERSION}"
}

install_hashcat_utils() {
    log_info "Installing hashcat-utils..."

    cd /tmp
    rm -rf hashcat-utils
    git clone --depth 1 https://github.com/hashcat/hashcat-utils.git
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
            https://github.com/danielmiessler/SecLists.git
        cd SecLists
        git sparse-checkout set Passwords
        cd ..
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
            "https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule"
    fi

    # Best64
    if [[ ! -f "best64.rule" ]]; then
        wget -q --show-progress -O best64.rule \
            "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/best64.rule"
    fi

    # d3ad0ne
    if [[ ! -f "d3ad0ne.rule" ]]; then
        wget -q --show-progress -O d3ad0ne.rule \
            "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/d3ad0ne.rule"
    fi

    # dive
    if [[ ! -f "dive.rule" ]]; then
        wget -q --show-progress -O dive.rule \
            "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/dive.rule"
    fi

    # Hob0Rules
    if [[ ! -f "hob064.rule" ]]; then
        wget -q --show-progress -O hob064.rule \
            "https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/hob064.rule"
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
    systemctl reload nginx

    # Check status
    sleep 2
    if systemctl is-active --quiet hm1k; then
        log_success "HM1K service is running"
    else
        log_error "HM1K service failed to start. Check: journalctl -u hm1k"
    fi

    if systemctl is-active --quiet nginx; then
        log_success "Nginx is running"
    else
        log_error "Nginx failed to start. Check: nginx -t"
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
    systemctl status hm1k --no-pager -l | head -10
    echo ""

    # Nginx
    echo "Nginx Status:"
    systemctl status nginx --no-pager | head -5
    echo ""

    # Test local connection
    echo "Testing local connection..."
    if curl -sk https://localhost/health 2>/dev/null | grep -q "ok\|healthy"; then
        log_success "HM1K responding on https://localhost"
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

    # Summary
    echo "============================================"
    echo "       Installation Summary"
    echo "============================================"
    echo ""
    echo "HM1K URL:        https://$(hostname -I | awk '{print $1}')"
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
    log_warn "IMPORTANT: Change the default admin password in ${HM1K_HOME}/.env"
    echo ""
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
    detect_cpu_info

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

    log_success "Deployment complete!"
}

main "$@"
