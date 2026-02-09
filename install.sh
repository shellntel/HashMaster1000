#!/bin/bash
#
# Hash Master 1000 - Quick Install Script (Linux/macOS)
#
# This script sets up HM1K for local development/testing.
# For production deployment, use scripts/deploy_production.sh instead.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/shellntel/hm1k/main/install.sh | bash
#   or
#   ./install.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo ""
echo "============================================"
echo "   Hash Master 1000 - Quick Install"
echo "============================================"
echo ""

# Check for Python 3.10+
log_info "Checking Python version..."
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

    if [[ "$PY_MAJOR" -ge 3 ]] && [[ "$PY_MINOR" -ge 10 ]]; then
        log_success "Found Python $PY_VERSION"
    else
        log_error "Python 3.10+ required, found $PY_VERSION. Please upgrade Python."
    fi
else
    log_error "Python 3 not found. Please install Python 3.10 or newer."
fi

# Determine install directory
if [[ -f "hm1k.py" ]]; then
    INSTALL_DIR="$(pwd)"
    log_info "Installing in current directory: $INSTALL_DIR"
else
    INSTALL_DIR="$HOME/hm1k"
    log_info "Installing to: $INSTALL_DIR"

    if [[ -d "$INSTALL_DIR" ]]; then
        log_warn "Directory exists. Pulling latest changes..."
        cd "$INSTALL_DIR"
        git pull 2>/dev/null || log_warn "Could not pull updates"
    else
        log_info "Cloning repository..."
        git clone https://github.com/shellntel/hm1k.git "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
fi

# Create virtual environment
log_info "Creating virtual environment..."
if [[ -d ".venv" ]]; then
    log_info "Virtual environment exists, skipping creation"
else
    python3 -m venv .venv
fi
log_success "Virtual environment ready"

# Activate and install dependencies
log_info "Installing Python dependencies..."
source .venv/bin/activate

pip install --upgrade pip wheel setuptools -q
pip install -r requirements.txt -q

log_success "Dependencies installed"

# Download NLTK data
log_info "Downloading NLTK data..."
python3 -c "
import nltk
import os
nltk_data = os.path.expanduser('~/nltk_data')
os.makedirs(nltk_data, exist_ok=True)
for pkg in ['words', 'names', 'averaged_perceptron_tagger', 'punkt']:
    try:
        nltk.download(pkg, download_dir=nltk_data, quiet=True)
    except:
        pass
" 2>/dev/null || log_warn "Some NLTK data could not be downloaded"
log_success "NLTK data ready"

# Create .env file if needed
if [[ ! -f ".env" ]]; then
    log_info "Creating .env file..."
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    INSTALL_DIR="$(pwd)"
    cat > .env << EOF
# Hash Master 1000 Configuration
SECRET_KEY="${SECRET_KEY}"
ADMIN_USERNAME="admin"
# Default password: Winter2026##
ADMIN_PASSWORD_HASH="\$2b\$12\$PzAkEQKfwFcafUK2RH08zO9Os3YFz7rq.4UqwaLHlFONDlqxncmnO"
# Default test data paths
DEFAULT_ADD_JSON_PATH="${INSTALL_DIR}/testData/example_ADD.json"
DEFAULT_POTFILE_PATH="${INSTALL_DIR}/testData/example.potfile"
EOF
    log_success "Created .env with default credentials (admin / Winter2026##)"
else
    log_info ".env file exists, skipping"
fi

# Create data directories
mkdir -p data/sessions data/uploads flask_session 2>/dev/null || true

# Generate SSL certificates for HTTPS
if [[ ! -f "cert.pem" ]] || [[ ! -f "key.pem" ]]; then
    log_info "Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=HM1K/CN=localhost" 2>/dev/null
    log_success "SSL certificate generated"
else
    log_info "SSL certificates exist, skipping"
fi

# Create start script
cat > start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source .venv/bin/activate
echo "Starting Hash Master 1000..."
echo "Access at: https://127.0.0.1:8443"
echo "Login: admin / Winter2026## (unless changed)"
echo ""
python3 hm1k.py
EOF
chmod +x start.sh

echo ""
echo "============================================"
echo "   Installation Complete!"
echo "============================================"
echo ""
echo "To start Hash Master 1000:"
echo ""
echo "  cd $INSTALL_DIR"
echo "  ./start.sh"
echo ""
echo "Or manually:"
echo "  source .venv/bin/activate"
echo "  python3 hm1k.py"
echo ""
echo "Access the app at: https://127.0.0.1:8443"
echo "Default login: admin / Winter2026##"
echo ""
log_warn "Change the default password in .env for security!"
echo ""
