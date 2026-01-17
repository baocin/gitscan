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

# Clear cache to force fresh scans
echo "Clearing cache..."
rm -rf /var/lib/gitvet/cache/*

# Start service
echo "Starting service..."
systemctl start gitvet

echo ""
echo "=== Update Complete ==="
systemctl status gitvet --no-pager
echo ""
echo "View logs: journalctl -u gitvet -f"
