#!/bin/bash
set -e

# git.vet Hetzner Deployment Script
# Run as root on a fresh Ubuntu 22.04+ server

echo "=== git.vet Deployment ==="

# Install dependencies
apt-get update
apt-get install -y git golang-go python3 python3-pip

# Install opengrep (semgrep-compatible scanner)
pip3 install opengrep || pip3 install semgrep

# Verify scanner is installed and determine which one
SCANNER_PATH=""
if command -v opengrep &> /dev/null; then
    SCANNER_PATH="opengrep"
    echo "Found opengrep: $(which opengrep)"
elif command -v semgrep &> /dev/null; then
    SCANNER_PATH="semgrep"
    echo "Found semgrep: $(which semgrep)"
else
    echo "ERROR: Neither opengrep nor semgrep installed!"
    exit 1
fi

# Create app user
useradd -r -s /bin/false gitvet || true

# Create directories
mkdir -p /opt/gitvet
mkdir -p /var/lib/gitvet/cache
mkdir -p /var/lib/gitvet/data
chown -R gitvet:gitvet /var/lib/gitvet

# Build from source (or copy pre-built binary)
cd /tmp
if [ -d "gitscan" ]; then rm -rf gitscan; fi
git clone https://github.com/baocin/gitscan.git
cd gitscan
go build -o /opt/gitvet/git-vet-server ./cmd/gitscan-server
chown gitvet:gitvet /opt/gitvet/git-vet-server

# Install systemd service (note: EOF without quotes to allow variable expansion)
cat > /etc/systemd/system/gitvet.service << EOF
[Unit]
Description=git.vet Security Scanner
After=network.target

[Service]
Type=simple
User=gitvet
Group=gitvet
WorkingDirectory=/opt/gitvet
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/gitvet/git-vet-server \
    -listen :6633 \
    -db /var/lib/gitvet/data/gitvet.db \
    -cache-dir /var/lib/gitvet/cache \
    -opengrep $SCANNER_PATH
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/gitvet
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable gitvet
systemctl start gitvet

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Service status:"
systemctl status gitvet --no-pager
echo ""
echo "git.vet is running on http://localhost:6633"
echo ""
echo "Next steps:"
echo "1. Configure your Cloudflare tunnel to point git.vet -> localhost:6633"
echo "2. Check logs: journalctl -u gitvet -f"
echo ""
