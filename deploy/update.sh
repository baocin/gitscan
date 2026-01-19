#!/bin/bash

# git.vet Update Script
# Run as root: sudo ./deploy/update.sh
#
# This script performs a safe, atomic update with rollback capability

set -o pipefail  # Catch pipe failures, but don't use -e

TEMP_DIR="/tmp/gitscan"
INSTALL_DIR="/opt/gitvet"
BINARY_NAME="gitvet-server"
SERVICE_NAME="gitvet"
BACKUP_SUFFIX=".backup.$(date +%s)"

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

fatal_error() {
    log_error "$1"
    if [ -n "$2" ]; then
        echo "$2"
    fi
    exit 1
}

# Pre-flight checks
log_info "Running pre-flight checks..."

if [ "$EUID" -ne 0 ]; then
    fatal_error "This script must be run as root" "Usage: sudo $0"
fi

if ! command -v git &> /dev/null; then
    fatal_error "git is not installed" "Install with: apt-get install git"
fi

if ! command -v go &> /dev/null; then
    fatal_error "go is not installed" "Install from: https://go.dev/dl/"
fi

if ! systemctl list-unit-files | grep -q "$SERVICE_NAME"; then
    log_warn "Service $SERVICE_NAME not found, will skip service operations"
fi

log_info "Pre-flight checks passed"
echo ""
echo "=== Updating git.vet ==="

# Stop service first
log_info "Stopping service..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    if ! systemctl stop "$SERVICE_NAME"; then
        log_warn "Failed to stop service, continuing anyway..."
    fi
else
    log_info "Service already stopped"
fi

# Clean start - forcefully remove old temp directory
log_info "Cleaning temporary directory..."
if [ -d "$TEMP_DIR" ]; then
    # Try normal removal first
    if ! rm -rf "$TEMP_DIR" 2>/dev/null; then
        # If that fails, try with elevated permissions
        log_warn "Permission issue detected, forcing cleanup..."
        if ! sudo rm -rf "$TEMP_DIR" 2>/dev/null; then
            # Last resort: change ownership then remove
            sudo chown -R root:root "$TEMP_DIR" 2>/dev/null || true
            sudo chmod -R u+rwX "$TEMP_DIR" 2>/dev/null || true
            if ! rm -rf "$TEMP_DIR" 2>/dev/null; then
                fatal_error "Cannot remove $TEMP_DIR - manual cleanup required"
            fi
        fi
    fi
fi

# Clone fresh copy
log_info "Cloning latest code from GitHub..."
cd /tmp
if ! git clone --depth 1 --branch main https://github.com/baocin/gitscan.git 2>&1; then
    fatal_error "Failed to clone repository" "Check your network connection and GitHub access"
fi

if [ ! -d "$TEMP_DIR" ]; then
    fatal_error "Clone succeeded but directory $TEMP_DIR not found"
fi

cd "$TEMP_DIR" || fatal_error "Cannot cd to $TEMP_DIR"

# Build binary
log_info "Building binary..."
BUILD_OUTPUT=$(go build -o "$BINARY_NAME" ./cmd/gitscan-server 2>&1)
BUILD_EXIT=$?

if [ $BUILD_EXIT -ne 0 ]; then
    echo "$BUILD_OUTPUT"
    fatal_error "Build failed with exit code $BUILD_EXIT"
fi

# Verify binary was created and is executable
if [ ! -f "$BINARY_NAME" ]; then
    fatal_error "Build completed but binary '$BINARY_NAME' not found"
fi

if [ ! -x "$BINARY_NAME" ]; then
    log_warn "Binary not executable, fixing permissions..."
    chmod +x "$BINARY_NAME"
fi

# Test binary can run
log_info "Verifying binary..."
if ! ./"$BINARY_NAME" --help &>/dev/null; then
    # Some binaries don't have --help, try -h or version
    if ! ./"$BINARY_NAME" -h &>/dev/null && ! ./"$BINARY_NAME" version &>/dev/null; then
        log_warn "Cannot verify binary execution (--help/-h/version all failed), proceeding anyway..."
    fi
fi

# Backup existing binary
BACKUP_PATH="$INSTALL_DIR/$BINARY_NAME$BACKUP_SUFFIX"
if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    log_info "Backing up existing binary to $BACKUP_PATH"
    if ! cp "$INSTALL_DIR/$BINARY_NAME" "$BACKUP_PATH"; then
        log_warn "Failed to create backup, continuing without backup..."
        BACKUP_PATH=""
    fi
else
    log_info "No existing binary to backup (fresh install)"
    BACKUP_PATH=""
fi

# Install binary
log_info "Installing binary to $INSTALL_DIR..."
if ! cp "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"; then
    fatal_error "Failed to copy binary to $INSTALL_DIR"
fi

if ! chown gitvet:gitvet "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null; then
    log_warn "Failed to set ownership to gitvet:gitvet, file may still be owned by root"
fi

# Grant capability to bind to privileged ports (< 1024)
log_info "Granting capability to bind to privileged ports..."
if setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/$BINARY_NAME"; then
    # Verify capability was set
    CURRENT_CAP=$(getcap "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null)
    if [[ "$CURRENT_CAP" == *"cap_net_bind_service"* ]]; then
        log_info "Capability set successfully: $CURRENT_CAP"
    else
        log_warn "Capability may not have been set correctly. Current: $CURRENT_CAP"
    fi
else
    log_error "Failed to set capability - privileged ports (22, 80, 443) will not work!"
    log_warn "You may need to run manually: sudo setcap 'cap_net_bind_service=+ep' $INSTALL_DIR/$BINARY_NAME"
fi

# Update systemd service configuration
log_info "Updating systemd service configuration..."
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

# Detect scanner (opengrep or semgrep)
SCANNER_PATH="opengrep"
if ! command -v opengrep &> /dev/null; then
    if command -v semgrep &> /dev/null; then
        SCANNER_PATH="semgrep"
    fi
fi

# Create backup if service file exists
if [ -f "$SERVICE_FILE" ]; then
    cp "$SERVICE_FILE" "$SERVICE_FILE.bak"
fi

# Write complete service file (simpler than trying to sed multi-line ExecStart)
cat > "$SERVICE_FILE" << 'SERVICEEOF'
[Unit]
Description=git.vet Security Scanner
After=network.target

[Service]
Type=simple
User=gitvet
Group=gitvet
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
WorkingDirectory=/opt/gitvet
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
Environment="XDG_CACHE_HOME=/var/lib/gitvet/cache"
Environment="XDG_CONFIG_HOME=/var/lib/gitvet"
Environment="SEMGREP_SEND_METRICS=off"
ExecStart=/opt/gitvet/gitvet-server -listen :80 -tls-listen :443 -tls-cert /etc/letsencrypt/live/git.vet/fullchain.pem -tls-key /etc/letsencrypt/live/git.vet/privkey.pem -ssh-listen :22 -enable-ssh=true -db /var/lib/gitvet/data/gitvet.db -cache-dir /var/lib/gitvet/cache -opengrep SCANNER_PATH_PLACEHOLDER
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/gitvet
ReadOnlyPaths=/etc/letsencrypt
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Replace scanner path placeholder
sed -i "s/SCANNER_PATH_PLACEHOLDER/$SCANNER_PATH/g" "$SERVICE_FILE"

log_info "Updated systemd service to use $BINARY_NAME with HTTP :80, HTTPS :443, SSH :22"
systemctl daemon-reload
rm -f "$SERVICE_FILE.bak"

# Ensure gitvet user has certificate access
log_info "Configuring certificate permissions..."
# Add gitvet to ssl-cert group if it exists
if getent group ssl-cert &>/dev/null; then
    if ! groups gitvet | grep -q ssl-cert; then
        usermod -a -G ssl-cert gitvet
        log_info "Added gitvet to ssl-cert group"
    else
        log_info "gitvet already in ssl-cert group"
    fi
fi

# Set ACLs on Let's Encrypt certificates (if they exist)
if [ -d /etc/letsencrypt/live ]; then
    if command -v setfacl &>/dev/null; then
        setfacl -R -m u:gitvet:rX /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
        log_info "Set ACLs on Let's Encrypt certificates for gitvet user"
    else
        # Fallback: set group permissions
        chgrp -R ssl-cert /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
        chmod -R g+rX /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
        log_info "Set group permissions on Let's Encrypt certificates"
    fi
else
    log_warn "Let's Encrypt certificates not found at /etc/letsencrypt/live"
fi

# Clear cache and reset database if needed
log_info "Resetting cache..."
# Look for reset_cache.sh: installed location, temp directory, or script directory
RESET_CACHE_SCRIPT=""
if [ -f "/opt/gitvet/scripts/reset_cache.sh" ]; then
    RESET_CACHE_SCRIPT="/opt/gitvet/scripts/reset_cache.sh"
elif [ -f "$TEMP_DIR/deploy/reset_cache.sh" ]; then
    RESET_CACHE_SCRIPT="$TEMP_DIR/deploy/reset_cache.sh"
elif [ -f "./deploy/reset_cache.sh" ]; then
    RESET_CACHE_SCRIPT="./deploy/reset_cache.sh"
elif [ -f "$(dirname "${BASH_SOURCE[0]}")/reset_cache.sh" ]; then
    RESET_CACHE_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/reset_cache.sh"
fi

if [ -n "$RESET_CACHE_SCRIPT" ]; then
    if ! "$RESET_CACHE_SCRIPT" --quiet; then
        log_warn "Cache reset failed, continuing anyway..."
    fi
else
    log_warn "reset_cache.sh not found, skipping cache reset"
fi

# Install/update opengrep if needed
if ! command -v opengrep &> /dev/null || ! opengrep --version &> /dev/null; then
    log_info "Installing opengrep..."
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v1.15.1/opengrep_manylinux_aarch64"
    else
        OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v1.15.1/opengrep_manylinux_x86"
    fi

    if curl -L -o /tmp/opengrep-bin "$OPENGREP_URL" && \
       chmod +x /tmp/opengrep-bin && \
       mv /tmp/opengrep-bin /usr/local/bin/opengrep; then
        log_info "opengrep installed: $(opengrep --version 2>&1 | head -1)"
    else
        log_warn "Failed to install opengrep, service may not function correctly"
    fi
else
    log_info "opengrep already installed: $(opengrep --version 2>&1 | head -1)"
fi

# Start service
log_info "Starting service..."
if ! systemctl start "$SERVICE_NAME"; then
    log_error "Failed to start service!"

    # Attempt rollback if we have a backup
    if [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH" ]; then
        log_warn "Attempting rollback to previous version..."
        if cp "$BACKUP_PATH" "$INSTALL_DIR/$BINARY_NAME" && \
           chown gitvet:gitvet "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null && \
           systemctl start "$SERVICE_NAME"; then
            log_info "Rollback successful, service started with previous version"
            fatal_error "Update failed but rollback succeeded" "Check logs: journalctl -u $SERVICE_NAME -n 50"
        else
            fatal_error "Update AND rollback both failed!" "Manual intervention required. Check: journalctl -u $SERVICE_NAME -n 50"
        fi
    else
        fatal_error "Service failed to start and no backup available for rollback" "Check logs: journalctl -u $SERVICE_NAME -n 50"
    fi
fi

# Verify service is actually running
sleep 2
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    log_error "Service started but is not running!"
    fatal_error "Service crashed after start" "Check logs: journalctl -u $SERVICE_NAME -n 50"
fi

# Update the deployment scripts themselves (self-update)
log_info "Updating deployment scripts..."
if [ -d "/opt/gitvet/scripts" ]; then
    if cp "$TEMP_DIR/deploy/update.sh" /opt/gitvet/scripts/update.sh && \
       cp "$TEMP_DIR/deploy/reset_cache.sh" /opt/gitvet/scripts/reset_cache.sh; then
        chmod 755 /opt/gitvet/scripts/update.sh /opt/gitvet/scripts/reset_cache.sh
        log_info "Deployment scripts updated"
    else
        log_warn "Failed to update deployment scripts, continuing anyway..."
    fi
else
    log_warn "Scripts directory /opt/gitvet/scripts not found, skipping script update"
fi

# Clean up backup on successful update
if [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH" ]; then
    log_info "Cleaning up backup..."
    rm -f "$BACKUP_PATH"
fi

# Clean up temp directory
log_info "Cleaning up temporary files..."
cd /tmp
rm -rf "$TEMP_DIR" 2>/dev/null || log_warn "Failed to clean up $TEMP_DIR, ignoring..."

echo ""
log_info "=== Update Complete ==="
systemctl status "$SERVICE_NAME" --no-pager
echo ""
echo "View logs: journalctl -u $SERVICE_NAME -f"
echo "Test HTTP: curl http://localhost:80/github.com/baocin/gitscan"
echo "Test HTTPS: curl https://git.vet/github.com/baocin/gitscan"
echo "Test SSH: git clone ssh://git.vet/github.com/baocin/gitscan"
echo ""
echo "Note: Database persists across updates (scan history preserved)"
echo "To reset database: sudo rm /var/lib/gitvet/data/gitvet.db && sudo systemctl restart gitvet"
