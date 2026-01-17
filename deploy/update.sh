#!/bin/bash
set -e

# git.vet Update Script
# Run as root to update to latest version

echo "=== Updating git.vet ==="

# Stop service first for clean update
echo "Stopping service..."
systemctl stop gitvet || true

# Clone fresh copy
cd /tmp
rm -rf gitscan
echo "Cloning latest code..."
git clone --depth 1 https://github.com/baocin/gitscan.git
cd gitscan

# Build
echo "Building binary..."
go build -o /opt/gitvet/git-vet-server ./cmd/gitscan-server
chown gitvet:gitvet /opt/gitvet/git-vet-server

# Restart
echo "Starting service..."
systemctl start gitvet

echo ""
echo "=== Update Complete ==="
systemctl status gitvet --no-pager
echo ""
echo "View logs: journalctl -u gitvet -f"
