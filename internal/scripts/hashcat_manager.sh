#!/bin/bash
#
# Hashcat Version Manager
#
# Manage multiple hashcat installations for benchmarking and testing
#
# Usage:
#   hashcat_manager.sh install <version>     - Install specific version
#   hashcat_manager.sh list                  - List installed versions
#   hashcat_manager.sh use <version>         - Set default version
#   hashcat_manager.sh benchmark [mode]      - Benchmark all versions
#   hashcat_manager.sh compare <v1> <v2>     - Compare two versions
#   hashcat_manager.sh info                  - Show system info
#

set -e

# Configuration
HASHCAT_HOME="${HASHCAT_HOME:-/opt/hashcat}"
VERSIONS_DIR="${HASHCAT_HOME}/versions"
WORDLISTS_DIR="${WORDLISTS_DIR:-/opt/wordlists}"
RULES_DIR="${RULES_DIR:-/opt/rules}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Helper Functions
# =============================================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This operation requires root privileges"
        exit 1
    fi
}

# =============================================================================
# Commands
# =============================================================================

cmd_list() {
    echo ""
    echo "Installed Hashcat Versions"
    echo "=========================="
    echo ""

    # System hashcat
    if command -v hashcat &>/dev/null; then
        local SYS_PATH=$(which hashcat)
        local SYS_VERSION=$(hashcat --version 2>/dev/null | head -1)
        local SYS_REAL=$(readlink -f "$SYS_PATH" 2>/dev/null || echo "$SYS_PATH")

        if [[ "$SYS_REAL" == "/usr/bin/hashcat" ]]; then
            echo -e "  ${GREEN}*${NC} system (apt)    : ${SYS_VERSION}"
            echo "                      Path: ${SYS_PATH}"
        else
            echo "    system (apt)    : ${SYS_VERSION:-not installed}"
        fi
    fi

    echo ""

    # Custom versions
    if [[ -d "$VERSIONS_DIR" ]]; then
        local CURRENT_DEFAULT=""
        if [[ -L /usr/local/bin/hashcat ]]; then
            CURRENT_DEFAULT=$(readlink -f /usr/local/bin/hashcat)
        fi

        for dir in "${VERSIONS_DIR}/"*/; do
            if [[ -d "$dir" ]] && [[ -f "${dir}hashcat" ]]; then
                local VERSION=$(basename "$dir")
                local VER_STRING=$("${dir}hashcat" --version 2>/dev/null | head -1 || echo "unknown")
                local VER_PATH="${dir}hashcat"

                if [[ "$CURRENT_DEFAULT" == "$VER_PATH" ]]; then
                    echo -e "  ${GREEN}*${NC} ${VERSION}         : ${VER_STRING}"
                else
                    echo "    ${VERSION}         : ${VER_STRING}"
                fi
                echo "                      Path: ${VER_PATH}"
            fi
        done
    else
        echo "  No custom versions installed"
    fi

    echo ""
    echo "* = current default"
    echo ""
}

cmd_install() {
    local VERSION="$1"

    if [[ -z "$VERSION" ]]; then
        log_error "Usage: $0 install <version>"
        echo "Example: $0 install 6.2.6"
        exit 1
    fi

    check_root

    local INSTALL_DIR="${VERSIONS_DIR}/${VERSION}"

    if [[ -d "$INSTALL_DIR" ]] && [[ -f "${INSTALL_DIR}/hashcat" ]]; then
        log_warn "Version ${VERSION} already installed at ${INSTALL_DIR}"
        "${INSTALL_DIR}/hashcat" --version
        exit 0
    fi

    log_info "Installing hashcat ${VERSION}..."

    mkdir -p "$INSTALL_DIR"
    cd /tmp

    # Try to clone with version tag
    rm -rf "hashcat-build-${VERSION}"

    if git clone --branch "v${VERSION}" --depth 1 https://github.com/hashcat/hashcat.git "hashcat-build-${VERSION}" 2>/dev/null; then
        log_info "Cloned tag v${VERSION}"
    elif git clone --branch "${VERSION}" --depth 1 https://github.com/hashcat/hashcat.git "hashcat-build-${VERSION}" 2>/dev/null; then
        log_info "Cloned branch ${VERSION}"
    else
        log_error "Could not find hashcat version ${VERSION}"
        log_info "Available tags: https://github.com/hashcat/hashcat/tags"
        rm -rf "hashcat-build-${VERSION}"
        exit 1
    fi

    cd "hashcat-build-${VERSION}"

    log_info "Building hashcat ${VERSION}..."
    make -j$(nproc)

    log_info "Installing to ${INSTALL_DIR}..."
    cp -r hashcat charsets layouts masks modules OpenCL rules "$INSTALL_DIR/" 2>/dev/null || true
    cp hashcat "$INSTALL_DIR/"

    # Create version-specific symlink
    ln -sf "${INSTALL_DIR}/hashcat" "/usr/local/bin/hashcat-${VERSION}"

    # Cleanup
    cd /tmp
    rm -rf "hashcat-build-${VERSION}"

    log_success "Hashcat ${VERSION} installed"
    "${INSTALL_DIR}/hashcat" --version
}

cmd_use() {
    local VERSION="$1"

    if [[ -z "$VERSION" ]]; then
        log_error "Usage: $0 use <version>"
        echo "Use '$0 list' to see available versions"
        exit 1
    fi

    check_root

    local VERSION_PATH="${VERSIONS_DIR}/${VERSION}/hashcat"

    if [[ "$VERSION" == "system" ]]; then
        rm -f /usr/local/bin/hashcat
        log_success "Switched to system hashcat (apt)"
        hashcat --version
        return
    fi

    if [[ ! -f "$VERSION_PATH" ]]; then
        log_error "Version ${VERSION} not found"
        echo "Use '$0 list' to see available versions"
        exit 1
    fi

    ln -sf "$VERSION_PATH" /usr/local/bin/hashcat
    log_success "Switched to hashcat ${VERSION}"
    /usr/local/bin/hashcat --version
}

cmd_benchmark() {
    local HASH_MODE="${1:-1000}"
    local OUTPUT_FILE="/tmp/hashcat_benchmark_$(date +%Y%m%d_%H%M%S).txt"

    echo ""
    echo "============================================"
    echo "  Hashcat Multi-Version Benchmark"
    echo "============================================"
    echo ""
    echo "Hash Mode: ${HASH_MODE} ($(get_hash_name $HASH_MODE))"
    echo "Output:    ${OUTPUT_FILE}"
    echo ""

    {
        echo "Hashcat Multi-Version Benchmark"
        echo "==============================="
        echo "Date:      $(date)"
        echo "Hash Mode: ${HASH_MODE} ($(get_hash_name $HASH_MODE))"
        echo "System:    $(uname -a)"
        echo "CPU:       $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
        echo "Cores:     $(nproc)"
        echo ""

        # OpenCL info
        echo "OpenCL Devices:"
        clinfo -l 2>/dev/null || echo "  (clinfo not available)"
        echo ""

        echo "============================================"

        # System hashcat
        if [[ -f /usr/bin/hashcat ]]; then
            echo ""
            echo "=== System hashcat (apt) ==="
            /usr/bin/hashcat --version
            echo ""
            /usr/bin/hashcat -b -m "$HASH_MODE" --force 2>&1 || echo "(benchmark failed)"
        fi

        # Custom versions
        for dir in "${VERSIONS_DIR}/"*/; do
            if [[ -d "$dir" ]] && [[ -f "${dir}hashcat" ]]; then
                VERSION=$(basename "$dir")
                echo ""
                echo "=== Hashcat ${VERSION} ==="
                "${dir}hashcat" --version 2>&1
                echo ""
                "${dir}hashcat" -b -m "$HASH_MODE" --force 2>&1 || echo "(benchmark failed)"
            fi
        done

        echo ""
        echo "============================================"
        echo "Benchmark complete: $(date)"

    } | tee "$OUTPUT_FILE"

    echo ""
    log_success "Results saved to: ${OUTPUT_FILE}"
}

cmd_compare() {
    local V1="$1"
    local V2="$2"
    local HASH_MODE="${3:-1000}"

    if [[ -z "$V1" ]] || [[ -z "$V2" ]]; then
        log_error "Usage: $0 compare <version1> <version2> [hash_mode]"
        exit 1
    fi

    local PATH1="${VERSIONS_DIR}/${V1}/hashcat"
    local PATH2="${VERSIONS_DIR}/${V2}/hashcat"

    [[ "$V1" == "system" ]] && PATH1="/usr/bin/hashcat"
    [[ "$V2" == "system" ]] && PATH2="/usr/bin/hashcat"

    if [[ ! -f "$PATH1" ]]; then
        log_error "Version ${V1} not found"
        exit 1
    fi
    if [[ ! -f "$PATH2" ]]; then
        log_error "Version ${V2} not found"
        exit 1
    fi

    echo ""
    echo "Comparing hashcat versions"
    echo "=========================="
    echo "Version 1: ${V1} ($("$PATH1" --version 2>/dev/null))"
    echo "Version 2: ${V2} ($("$PATH2" --version 2>/dev/null))"
    echo "Hash Mode: ${HASH_MODE}"
    echo ""

    echo "=== ${V1} Benchmark ==="
    "$PATH1" -b -m "$HASH_MODE" --force 2>&1 | grep -E "Speed|Hash"

    echo ""
    echo "=== ${V2} Benchmark ==="
    "$PATH2" -b -m "$HASH_MODE" --force 2>&1 | grep -E "Speed|Hash"
}

cmd_info() {
    echo ""
    echo "System Information"
    echo "=================="
    echo ""

    # CPU
    echo "CPU:"
    echo "  Model:  $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    echo "  Cores:  $(nproc)"
    echo "  MHz:    $(grep -m1 'cpu MHz' /proc/cpuinfo | cut -d: -f2 | xargs)"

    # Memory
    echo ""
    echo "Memory:"
    free -h | grep -E "Mem|Swap" | awk '{print "  " $0}'

    # Storage
    echo ""
    echo "Storage:"
    df -h / | tail -1 | awk '{print "  Root: " $4 " available of " $2}'
    df -h "$HASHCAT_HOME" 2>/dev/null | tail -1 | awk '{print "  Hashcat: " $4 " available of " $2}' || true

    # OpenCL
    echo ""
    echo "OpenCL Devices:"
    if command -v clinfo &>/dev/null; then
        clinfo -l 2>/dev/null | sed 's/^/  /'
    else
        echo "  clinfo not installed"
    fi

    # Paths
    echo ""
    echo "Paths:"
    echo "  Hashcat Home: ${HASHCAT_HOME}"
    echo "  Versions:     ${VERSIONS_DIR}"
    echo "  Wordlists:    ${WORDLISTS_DIR}"
    echo "  Rules:        ${RULES_DIR}"

    # Wordlist sizes
    if [[ -d "$WORDLISTS_DIR" ]]; then
        echo ""
        echo "Wordlists:"
        ls -lhS "$WORDLISTS_DIR"/*.txt 2>/dev/null | head -10 | awk '{print "  " $9 ": " $5}' || echo "  (none found)"
    fi
}

get_hash_name() {
    local MODE=$1
    case $MODE in
        0)    echo "MD5" ;;
        100)  echo "SHA1" ;;
        1000) echo "NTLM" ;;
        1400) echo "SHA256" ;;
        1700) echo "SHA512" ;;
        2500) echo "WPA/WPA2" ;;
        3000) echo "LM" ;;
        5500) echo "NetNTLMv1" ;;
        5600) echo "NetNTLMv2" ;;
        13100) echo "Kerberos TGS-REP" ;;
        18200) echo "Kerberos AS-REP" ;;
        *)    echo "mode $MODE" ;;
    esac
}

cmd_help() {
    echo "Hashcat Version Manager"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  list                    List installed hashcat versions"
    echo "  install <version>       Install a specific hashcat version from source"
    echo "  use <version|system>    Set the default hashcat version"
    echo "  benchmark [mode]        Benchmark all versions (default: 1000/NTLM)"
    echo "  compare <v1> <v2>       Compare two specific versions"
    echo "  info                    Show system and hashcat information"
    echo ""
    echo "Examples:"
    echo "  $0 list"
    echo "  $0 install 6.2.5"
    echo "  $0 install 6.2.6"
    echo "  $0 use 6.2.6"
    echo "  $0 benchmark 1000"
    echo "  $0 compare 6.2.5 6.2.6"
    echo "  $0 compare system 6.2.6 13100"
    echo ""
    echo "Common hash modes for benchmarking:"
    echo "  0     - MD5"
    echo "  100   - SHA1"
    echo "  1000  - NTLM (default)"
    echo "  1400  - SHA256"
    echo "  3000  - LM"
    echo "  5600  - NetNTLMv2"
    echo "  13100 - Kerberos TGS-REP (Kerberoast)"
    echo "  18200 - Kerberos AS-REP"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

case "${1:-help}" in
    list)       cmd_list ;;
    install)    cmd_install "$2" ;;
    use)        cmd_use "$2" ;;
    benchmark)  cmd_benchmark "$2" ;;
    compare)    cmd_compare "$2" "$3" "$4" ;;
    info)       cmd_info ;;
    help|--help|-h) cmd_help ;;
    *)
        log_error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
