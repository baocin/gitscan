#!/bin/bash
set -e

# git.vet Update Script
# Run as root: sudo ./deploy/update.sh

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

echo "=== Updating git.vet ==="

# Stop service first
echo "Stopping service..."
systemctl stop gitvet || true

# Clone fresh copy from main
cd /tmp
rm -rf gitscan
echo "Cloning latest from main..."
git clone --depth 1 --branch main https://github.com/baocin/gitscan.git
cd gitscan

# Build locally first, then copy (avoids permission issues)
echo "Building binary..."
go build -o git-vet-server ./cmd/gitscan-server

echo "Installing binary..."
cp git-vet-server /opt/gitvet/git-vet-server
chown gitvet:gitvet /opt/gitvet/git-vet-server

# Clear cache and fix any malformed database entries
echo "Resetting cache..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR/reset_cache.sh" --quiet

# Install/update opengrep if needed
if ! command -v opengrep &> /dev/null || ! opengrep --version &> /dev/null; then
    echo "Installing opengrep..."
    rm -rf /usr/local/bin/opengrep
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v1.15.1/opengrep_manylinux_aarch64"
    else
        OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v1.15.1/opengrep_manylinux_x86"
    fi
    curl -L -o /tmp/opengrep-bin "$OPENGREP_URL"
    chmod +x /tmp/opengrep-bin
    mv /tmp/opengrep-bin /usr/local/bin/opengrep
    echo "opengrep installed: $(opengrep --version 2>&1 | head -1)"
else
    echo "opengrep already installed: $(opengrep --version 2>&1 | head -1)"
fi

# Start service
echo "Starting service..."
systemctl start gitvet

echo ""
echo "=== Update Complete ==="
systemctl status gitvet --no-pager
echo ""
echo "View logs: journalctl -u gitvet -f"
