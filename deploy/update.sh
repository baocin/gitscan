#!/bin/bash

# git.vet Update Script
# Run as root: sudo ./deploy/update.sh
#
# This script performs a safe, atomic update with rollback capability

set -o pipefail  # Catch pipe failures, but don't use -e

TEMP_DIR="/tmp/gitscan"
INSTALL_DIR="/opt/gitvet"
BINARY_NAME="git-vet-server"
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

# Clear cache and reset database if needed
log_info "Resetting cache..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/reset_cache.sh" ]; then
    if ! "$SCRIPT_DIR/reset_cache.sh" --quiet; then
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
echo "Test service: curl http://localhost:6633/github.com/baocin/gitscan"
