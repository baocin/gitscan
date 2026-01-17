#!/bin/bash
set -e

# git.vet Update Script
# Run as root to update to latest version

echo "=== Updating git.vet ==="

cd /tmp
rm -rf gitscan
git clone https://github.com/baocin/gitscan.git
cd gitscan
go build -o /opt/gitvet/git-vet-server ./cmd/gitscan-server
chown gitvet:gitvet /opt/gitvet/git-vet-server

systemctl restart gitvet

echo ""
echo "=== Update Complete ==="
systemctl status gitvet --no-pager
