#!/bin/bash
#
# HM1K Agent Deployment Script
# Installs and configures the HM1K hashcat cracking agent
#
# Usage: sudo ./deploy.sh [OPTIONS]
#
# Options:
#   --no-service    Skip systemd service installation
#   --dev           Development mode (install from local source)
#   --uninstall     Remove the agent completely
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AGENT_USER="hm1k-agent"
AGENT_GROUP="hm1k-agent"
INSTALL_DIR="/opt/hm1k-agent"
CONFIG_DIR="/etc/hm1k-agent"
DATA_DIR="/var/lib/hm1k-agent"
LOG_DIR="/var/log/hm1k-agent"
VENV_DIR="${INSTALL_DIR}/venv"

# Parse arguments
INSTALL_SERVICE=true
DEV_MODE=false
UNINSTALL=false

for arg in "$@"; do
    case $arg in
        --no-service)
            INSTALL_SERVICE=false
            shift
            ;;
        --dev)
            DEV_MODE=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        --help|-h)
            echo "HM1K Agent Deployment Script"
            echo ""
            echo "Usage: sudo ./deploy.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-service    Skip systemd service installation"
            echo "  --dev           Development mode (install from local source)"
            echo "  --uninstall     Remove the agent completely"
            echo "  --help, -h      Show this help message"
            exit 0
            ;;
    esac
done

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$PRETTY_NAME
    else
        log_error "Cannot detect operating system"
        exit 1
    fi

    log_info "Detected OS: ${OS_NAME}"

    case $OS in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            PKG_UPDATE="apt-get update"
            ;;
        rhel|centos|rocky|almalinux|fedora)
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf check-update || true"
            if ! command -v dnf &> /dev/null; then
                PKG_MANAGER="yum"
                PKG_UPDATE="yum check-update || true"
            fi
            ;;
        *)
            log_warn "Unsupported OS: $OS. Proceeding anyway..."
            PKG_MANAGER="apt-get"
            PKG_UPDATE="apt-get update"
            ;;
    esac
}

# Uninstall function
uninstall_agent() {
    log_info "Uninstalling HM1K Agent..."

    # Stop and disable service
    if systemctl is-active --quiet hm1k-agent 2>/dev/null; then
        log_info "Stopping hm1k-agent service..."
        systemctl stop hm1k-agent
    fi

    if systemctl is-enabled --quiet hm1k-agent 2>/dev/null; then
        log_info "Disabling hm1k-agent service..."
        systemctl disable hm1k-agent
    fi

    # Remove service file
    if [[ -f /etc/systemd/system/hm1k-agent.service ]]; then
        rm -f /etc/systemd/system/hm1k-agent.service
        systemctl daemon-reload
        log_success "Removed systemd service"
    fi

    # Remove sudoers entry
    if [[ -f /etc/sudoers.d/hm1k-agent ]]; then
        rm -f /etc/sudoers.d/hm1k-agent
        log_success "Removed sudoers entry"
    fi

    # Remove directories
    for dir in "$INSTALL_DIR" "$LOG_DIR"; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir"
            log_success "Removed $dir"
        fi
    done

    # Ask about config and data
    echo ""
    read -p "Remove configuration directory ($CONFIG_DIR)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        log_success "Removed $CONFIG_DIR"
    fi

    read -p "Remove data directory ($DATA_DIR)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
        log_success "Removed $DATA_DIR"
    fi

    # Remove user
    if id "$AGENT_USER" &>/dev/null; then
        read -p "Remove $AGENT_USER user? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            userdel "$AGENT_USER" 2>/dev/null || true
            log_success "Removed user $AGENT_USER"
        fi
    fi

    # Remove symlink
    rm -f /usr/local/bin/hm1k-agent

    log_success "HM1K Agent uninstalled"
    exit 0
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."

    $PKG_UPDATE

    case $OS in
        ubuntu|debian)
            DEBIAN_FRONTEND=noninteractive $PKG_MANAGER install -y \
                python3 \
                python3-pip \
                python3-venv \
                python3-dev \
                build-essential \
                curl \
                git
            ;;
        rhel|centos|rocky|almalinux|fedora)
            $PKG_MANAGER install -y \
                python3 \
                python3-pip \
                python3-devel \
                gcc \
                curl \
                git
            ;;
    esac

    log_success "System dependencies installed"
}

# Check Python version
check_python() {
    log_info "Checking Python version..."

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 9 ]]; then
        log_error "Python 3.9+ required (found $PYTHON_VERSION)"
        exit 1
    fi

    log_success "Python $PYTHON_VERSION detected"
}

# Setup hashcat directory for agent-managed installations
# Hashcat must be deployed through Hash Master to ensure correct permissions
setup_hashcat_directory() {
    log_info "Setting up hashcat directory..."

    # Create /opt/hashcat owned by the agent user
    # The agent will install hashcat versions here via Hash Master
    if [[ ! -d "/opt/hashcat" ]]; then
        mkdir -p /opt/hashcat
        log_success "Created /opt/hashcat directory"
    fi

    # Set ownership so agent can install hashcat versions
    chown "$AGENT_USER:$AGENT_GROUP" /opt/hashcat
    chmod 755 /opt/hashcat

    # Fix permissions on any existing hashcat installations
    # (in case there are pre-existing manual installs)
    for dir in /opt/hashcat/hashcat-* /opt/hashcat/versions; do
        if [[ -d "$dir" ]]; then
            chown -R "$AGENT_USER:$AGENT_GROUP" "$dir"
            log_info "Fixed permissions: $dir"
        fi
    done

    # If there's a current symlink, fix the target directory
    if [[ -L "/opt/hashcat/current" ]]; then
        TARGET=$(readlink -f /opt/hashcat/current)
        if [[ -d "$TARGET" ]]; then
            chown -R "$AGENT_USER:$AGENT_GROUP" "$TARGET"
            log_info "Fixed permissions: $TARGET"
        fi
    fi

    log_success "Hashcat directory ready at /opt/hashcat"
    log_info "Deploy hashcat through Hash Master after agent registration"
}

# Create agent user
create_user() {
    log_info "Creating agent user..."

    if id "$AGENT_USER" &>/dev/null; then
        log_info "User $AGENT_USER already exists"
    else
        # Create system user with no login shell
        useradd --system --shell /usr/sbin/nologin --home-dir "$DATA_DIR" \
            --comment "HM1K Cracking Agent" "$AGENT_USER"
        log_success "Created user $AGENT_USER"
    fi

    # Add user to video group for GPU access
    if getent group video > /dev/null; then
        usermod -aG video "$AGENT_USER"
        log_success "Added $AGENT_USER to video group (GPU access)"
    fi

    # Add user to render group if it exists (newer systems)
    if getent group render > /dev/null; then
        usermod -aG render "$AGENT_USER"
        log_success "Added $AGENT_USER to render group"
    fi
}

# Create directory structure
create_directories() {
    log_info "Creating directory structure..."

    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    # Create all directories referenced in config.yaml
    mkdir -p "$DATA_DIR"/{cache,data,hashcat,jobs,potfiles,sessions}
    mkdir -p "$LOG_DIR"

    # Set ownership - agent user needs full access to data and log dirs
    chown -R "$AGENT_USER:$AGENT_GROUP" "$DATA_DIR"
    chown -R "$AGENT_USER:$AGENT_GROUP" "$LOG_DIR"
    chown root:$AGENT_GROUP "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"

    # Create potfile with correct ownership (prevents root ownership issues)
    touch "$DATA_DIR/potfiles/agent.potfile"
    chown "$AGENT_USER:$AGENT_GROUP" "$DATA_DIR/potfiles/agent.potfile"

    # Ensure proper permissions on subdirectories
    chmod -R 755 "$DATA_DIR"

    log_success "Created directories"
    log_info "  Data: $DATA_DIR/{cache,data,hashcat,jobs,potfiles,sessions}"
    log_info "  Logs: $LOG_DIR"
}

# Install the agent
install_agent() {
    log_info "Installing HM1K Agent..."

    # Create virtual environment
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"

    # Upgrade pip
    pip install --upgrade pip wheel setuptools

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ "$DEV_MODE" == true ]]; then
        # Install from local source (development)
        pip install -e "$SCRIPT_DIR"
        log_success "Installed agent in development mode"
    else
        # Check for pre-built wheel first (bootstrap install)
        WHEEL_FILE=$(ls "$SCRIPT_DIR"/*.whl 2>/dev/null | head -1)
        if [[ -n "$WHEEL_FILE" && -f "$WHEEL_FILE" ]]; then
            pip install "$WHEEL_FILE"
            log_success "Installed agent from wheel: $(basename "$WHEEL_FILE")"
        else
            # Fall back to installing from source
            pip install "$SCRIPT_DIR"
            log_success "Installed agent from source"
        fi
    fi

    deactivate

    # Ensure venv is readable by agent user (installed as root, runs as hm1k-agent)
    chmod -R a+rX "$INSTALL_DIR"

    # Create symlink for CLI
    ln -sf "$VENV_DIR/bin/hm1k-agent" /usr/local/bin/hm1k-agent

    log_success "Agent installed to $INSTALL_DIR"
}

# Install example config
install_config() {
    log_info "Installing configuration..."

    CONFIG_FILE="$CONFIG_DIR/config.yaml"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Config already exists at $CONFIG_FILE"
        log_info "Saving example as config.yaml.example"
        cp "$SCRIPT_DIR/config.example.yaml" "$CONFIG_DIR/config.yaml.example"
    else
        cp "$SCRIPT_DIR/config.example.yaml" "$CONFIG_FILE"
        chown root:$AGENT_GROUP "$CONFIG_FILE"
        chmod 640 "$CONFIG_FILE"
        log_success "Installed example config to $CONFIG_FILE"
    fi
}

# Install systemd service
install_service() {
    log_info "Installing systemd service..."

    cat > /etc/systemd/system/hm1k-agent.service << 'EOF'
[Unit]
Description=HM1K Hashcat Cracking Agent
Documentation=https://github.com/yourusername/hm1k
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hm1k-agent
Group=hm1k-agent

# Environment - include hashcat path for OpenCL kernels
Environment="PATH=/opt/hm1k-agent/venv/bin:/opt/hashcat/current:/usr/local/bin:/usr/bin:/bin"

# Execution
ExecStart=/opt/hm1k-agent/venv/bin/hm1k-agent run
ExecReload=/bin/kill -HUP $MAINPID

# Restart policy
Restart=always
RestartSec=10

# Security hardening
# ProtectSystem=strict: Filesystem is read-only except ReadWritePaths
# ProtectHome=true: No access to /home (hashcat must NOT be in home directory)
# PrivateTmp=true: Agent gets isolated /tmp directory
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hm1k-agent /var/log/hm1k-agent
PrivateTmp=true

# GPU access - video and render groups for NVIDIA/AMD GPU access
SupplementaryGroups=video render

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Installed systemd service"

    # Install sudoers entry to allow agent to restart itself (for self-updates)
    # Uses systemd-run --scope to escape the service cgroup during restart
    SUDOERS_FILE="/etc/sudoers.d/hm1k-agent"
    SUDOERS_ENTRY="$AGENT_USER ALL=(root) NOPASSWD: /usr/bin/systemd-run --scope --quiet /usr/bin/systemctl restart hm1k-agent"
    if [[ ! -f "$SUDOERS_FILE" ]] || ! grep -q "systemd-run" "$SUDOERS_FILE"; then
        echo "$SUDOERS_ENTRY" > "$SUDOERS_FILE"
        chmod 440 "$SUDOERS_FILE"
        log_success "Installed sudoers entry for self-restart"
    else
        log_info "Sudoers entry already exists"
    fi

    echo ""
    log_info "To enable and start the service:"
    echo "    sudo systemctl enable hm1k-agent"
    echo "    sudo systemctl start hm1k-agent"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."

    echo ""

    # Check CLI
    if /usr/local/bin/hm1k-agent --version &>/dev/null; then
        VERSION=$(/usr/local/bin/hm1k-agent --version)
        log_success "CLI working: $VERSION"
    else
        log_error "CLI not working"
    fi

    # Check directories
    for dir in "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"; do
        if [[ -d "$dir" ]]; then
            log_success "Directory exists: $dir"
        else
            log_error "Directory missing: $dir"
        fi
    done

    # Check user
    if id "$AGENT_USER" &>/dev/null; then
        log_success "User exists: $AGENT_USER"
    else
        log_error "User missing: $AGENT_USER"
    fi

    # Check hashcat
    if [[ -n "$HASHCAT_PATH" ]]; then
        # Test GPU detection
        echo ""
        log_info "Checking GPU devices..."
        if sudo -u "$AGENT_USER" "$HASHCAT_PATH" -I 2>/dev/null | head -20; then
            log_success "GPU detection working"
        else
            log_warn "Could not detect GPUs (may need driver configuration)"
        fi
    fi
}

# Print completion message
print_completion() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}HM1K Agent Installation Complete${NC}"
    echo "=============================================="
    echo ""
    echo "Installation Summary:"
    echo "  Install directory: $INSTALL_DIR"
    echo "  Config directory:  $CONFIG_DIR"
    echo "  Data directory:    $DATA_DIR"
    echo "  Log directory:     $LOG_DIR"
    echo ""
    echo "Next Steps:"
    echo ""
    echo "  1. Edit the configuration:"
    echo "     sudo nano $CONFIG_DIR/config.yaml"
    echo ""
    echo "  2. Run the setup wizard:"
    echo "     sudo hm1k-agent init"
    echo ""
    echo "  3. Test the agent:"
    echo "     hm1k-agent status"
    echo "     hm1k-agent benchmark"
    echo ""
    if [[ "$INSTALL_SERVICE" == true ]]; then
        echo "  4. Start the service:"
        echo "     sudo systemctl enable --now hm1k-agent"
        echo ""
    fi
    echo "  For help:"
    echo "     hm1k-agent --help"
    echo ""
}

# Main installation flow
main() {
    echo ""
    echo "=============================================="
    echo "       HM1K Agent Deployment Script"
    echo "=============================================="
    echo ""

    check_root

    if [[ "$UNINSTALL" == true ]]; then
        uninstall_agent
    fi

    detect_os
    install_dependencies
    check_python
    create_user
    setup_hashcat_directory
    create_directories
    install_agent
    install_config

    if [[ "$INSTALL_SERVICE" == true ]]; then
        install_service
    fi

    verify_installation
    print_completion
}

# Run main
main "$@"
