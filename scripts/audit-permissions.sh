#!/bin/bash
#
# HM1K Permissions Audit Script
# Checks and optionally fixes file permissions for HM1K server and agent
#
# Usage:
#   ./audit-permissions.sh          # Audit only (report issues)
#   ./audit-permissions.sh --fix    # Audit and fix issues
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FIX_MODE=false
if [[ "$1" == "--fix" ]]; then
    FIX_MODE=true
fi

ISSUES=0

log_ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
    ISSUES=$((ISSUES + 1))
}

log_error() {
    echo -e "  ${RED}✗${NC} $1"
    ISSUES=$((ISSUES + 1))
}

log_fix() {
    echo -e "  ${CYAN}→${NC} $1"
}

# ============================================================================
# HM1K Server Audit
# ============================================================================
audit_server() {
    local APP_DIR="/opt/hm1k"
    local SERVICE_USER="hm1k"

    echo -e "\n${BOLD}=== HM1K Server ($APP_DIR) ===${NC}"

    if [[ ! -d "$APP_DIR" ]]; then
        echo -e "  ${YELLOW}Not installed${NC}"
        return
    fi

    cd "$APP_DIR"

    # Check static file permissions
    echo -e "\n${CYAN}Static files:${NC}"
    local bad_files=$(find static -type f ! -perm 644 2>/dev/null | wc -l)
    local bad_dirs=$(find static -type d ! -perm 755 2>/dev/null | wc -l)

    if [[ "$bad_files" -eq 0 ]]; then
        log_ok "All static files have correct permissions (644)"
    else
        log_warn "$bad_files files have wrong permissions"
        find static -type f ! -perm 644 2>/dev/null | head -5 | while read f; do
            echo -e "      $(ls -la "$f" | awk '{print $1, $NF}')"
        done
        if $FIX_MODE; then
            log_fix "chmod 644 on static files"
            find static -type f -exec chmod 644 {} \;
        fi
    fi

    if [[ "$bad_dirs" -eq 0 ]]; then
        log_ok "All static directories have correct permissions (755)"
    else
        log_warn "$bad_dirs directories have wrong permissions"
        if $FIX_MODE; then
            log_fix "chmod 755 on static directories"
            find static -type d -exec chmod 755 {} \;
        fi
    fi

    # Check template permissions
    echo -e "\n${CYAN}Templates:${NC}"
    local bad_templates=$(find templates -type f ! -perm 644 2>/dev/null | wc -l)
    if [[ "$bad_templates" -eq 0 ]]; then
        log_ok "All templates have correct permissions (644)"
    else
        log_warn "$bad_templates templates have wrong permissions"
        if $FIX_MODE; then
            log_fix "chmod 644 on templates"
            find templates -type f -exec chmod 644 {} \;
        fi
    fi

    # Check runtime directory ownership
    echo -e "\n${CYAN}Runtime directories:${NC}"
    for dir in data logs flask_session uploads; do
        if [[ -d "$APP_DIR/$dir" ]]; then
            local owner=$(stat -c '%U:%G' "$APP_DIR/$dir" 2>/dev/null)
            if [[ "$owner" == "$SERVICE_USER:$SERVICE_USER" ]]; then
                log_ok "$dir/ owned by $owner"
            else
                log_warn "$dir/ owned by $owner (should be $SERVICE_USER:$SERVICE_USER)"
                if $FIX_MODE; then
                    log_fix "chown -R $SERVICE_USER:$SERVICE_USER $dir/"
                    sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/$dir"
                fi
            fi
        else
            log_warn "$dir/ does not exist"
            if $FIX_MODE; then
                log_fix "mkdir $dir && chown $SERVICE_USER:$SERVICE_USER $dir/"
                mkdir -p "$APP_DIR/$dir"
                sudo chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/$dir"
            fi
        fi
    done

    # Check sensitive file permissions
    echo -e "\n${CYAN}Sensitive files:${NC}"
    if [[ -f "$APP_DIR/key.pem" ]]; then
        local key_perms=$(stat -c '%a' "$APP_DIR/key.pem" 2>/dev/null)
        if [[ "$key_perms" == "640" || "$key_perms" == "600" ]]; then
            log_ok "key.pem has restricted permissions ($key_perms)"
        else
            log_warn "key.pem has permissions $key_perms (should be 640)"
            if $FIX_MODE; then
                log_fix "chmod 640 key.pem"
                chmod 640 "$APP_DIR/key.pem"
            fi
        fi
    fi

    if [[ -f "$APP_DIR/.env" ]]; then
        local env_perms=$(stat -c '%a' "$APP_DIR/.env" 2>/dev/null)
        if [[ "$env_perms" == "640" || "$env_perms" == "600" ]]; then
            log_ok ".env has restricted permissions ($env_perms)"
        else
            log_warn ".env has permissions $env_perms (should be 640)"
            if $FIX_MODE; then
                log_fix "chmod 640 .env"
                chmod 640 "$APP_DIR/.env"
            fi
        fi
    fi
}

# ============================================================================
# HM1K Agent Audit
# ============================================================================
audit_agent() {
    local AGENT_DIR="/opt/hm1k-agent"
    local SERVICE_USER="hm1k-agent"

    echo -e "\n${BOLD}=== HM1K Agent ($AGENT_DIR) ===${NC}"

    if [[ ! -d "$AGENT_DIR" ]]; then
        echo -e "  ${YELLOW}Not installed${NC}"
        return
    fi

    # Check venv ownership (CRITICAL for self-updates)
    echo -e "\n${CYAN}Virtual environment:${NC}"
    if [[ -d "$AGENT_DIR/venv" ]]; then
        local venv_owner=$(stat -c '%U:%G' "$AGENT_DIR/venv" 2>/dev/null)
        if [[ "$venv_owner" == "$SERVICE_USER:$SERVICE_USER" ]]; then
            log_ok "venv/ owned by $venv_owner"
        else
            log_error "venv/ owned by $venv_owner (should be $SERVICE_USER:$SERVICE_USER)"
            echo -e "      ${RED}This will prevent agent self-updates!${NC}"
            if $FIX_MODE; then
                log_fix "chown -R $SERVICE_USER:$SERVICE_USER venv/"
                sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$AGENT_DIR/venv"
            fi
        fi

        # Check for files inside venv not owned by service user
        local bad_venv_files=$(find "$AGENT_DIR/venv" ! -user "$SERVICE_USER" 2>/dev/null | wc -l)
        if [[ "$bad_venv_files" -gt 0 ]]; then
            log_warn "$bad_venv_files files inside venv/ not owned by $SERVICE_USER"
            if $FIX_MODE; then
                log_fix "chown -R $SERVICE_USER:$SERVICE_USER venv/"
                sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$AGENT_DIR/venv"
            fi
        fi
    else
        log_error "venv/ does not exist"
    fi

    # Check config directory
    echo -e "\n${CYAN}Configuration:${NC}"
    if [[ -d "/etc/hm1k-agent" ]]; then
        local config_owner=$(stat -c '%U:%G' "/etc/hm1k-agent" 2>/dev/null)
        if [[ "$config_owner" == "$SERVICE_USER:$SERVICE_USER" ]]; then
            log_ok "/etc/hm1k-agent/ owned by $config_owner"
        else
            log_warn "/etc/hm1k-agent/ owned by $config_owner (should be $SERVICE_USER:$SERVICE_USER)"
            if $FIX_MODE; then
                log_fix "chown -R $SERVICE_USER:$SERVICE_USER /etc/hm1k-agent/"
                sudo chown -R "$SERVICE_USER:$SERVICE_USER" "/etc/hm1k-agent"
            fi
        fi

        if [[ -f "/etc/hm1k-agent/config.yaml" ]]; then
            local config_perms=$(stat -c '%a' "/etc/hm1k-agent/config.yaml" 2>/dev/null)
            if [[ "$config_perms" == "640" || "$config_perms" == "600" ]]; then
                log_ok "config.yaml has restricted permissions ($config_perms)"
            else
                log_warn "config.yaml has permissions $config_perms (should be 640)"
                if $FIX_MODE; then
                    log_fix "chmod 640 /etc/hm1k-agent/config.yaml"
                    sudo chmod 640 "/etc/hm1k-agent/config.yaml"
                fi
            fi
        fi
    fi

    # Check log directory
    echo -e "\n${CYAN}Log directory:${NC}"
    if [[ -d "/var/log/hm1k-agent" ]]; then
        local log_owner=$(stat -c '%U:%G' "/var/log/hm1k-agent" 2>/dev/null)
        if [[ "$log_owner" == "$SERVICE_USER:$SERVICE_USER" ]]; then
            log_ok "/var/log/hm1k-agent/ owned by $log_owner"
        else
            log_warn "/var/log/hm1k-agent/ owned by $log_owner (should be $SERVICE_USER:$SERVICE_USER)"
            if $FIX_MODE; then
                log_fix "chown -R $SERVICE_USER:$SERVICE_USER /var/log/hm1k-agent/"
                sudo chown -R "$SERVICE_USER:$SERVICE_USER" "/var/log/hm1k-agent"
            fi
        fi
    fi

    # Check cache directory
    if [[ -d "/var/cache/hm1k-agent" ]]; then
        local cache_owner=$(stat -c '%U:%G' "/var/cache/hm1k-agent" 2>/dev/null)
        if [[ "$cache_owner" == "$SERVICE_USER:$SERVICE_USER" ]]; then
            log_ok "/var/cache/hm1k-agent/ owned by $cache_owner"
        else
            log_warn "/var/cache/hm1k-agent/ owned by $cache_owner (should be $SERVICE_USER:$SERVICE_USER)"
            if $FIX_MODE; then
                log_fix "chown -R $SERVICE_USER:$SERVICE_USER /var/cache/hm1k-agent/"
                sudo chown -R "$SERVICE_USER:$SERVICE_USER" "/var/cache/hm1k-agent"
            fi
        fi
    fi
}

# ============================================================================
# Main
# ============================================================================
echo -e "${BOLD}HM1K Permissions Audit${NC}"
echo -e "Mode: $($FIX_MODE && echo 'Audit + Fix' || echo 'Audit only')"

audit_server
audit_agent

echo -e "\n${BOLD}=== Summary ===${NC}"
if [[ "$ISSUES" -eq 0 ]]; then
    echo -e "${GREEN}All permissions OK${NC}"
else
    if $FIX_MODE; then
        echo -e "${YELLOW}Fixed $ISSUES permission issues${NC}"
    else
        echo -e "${YELLOW}Found $ISSUES permission issues${NC}"
        echo -e "Run with ${CYAN}--fix${NC} to correct them"
    fi
fi
