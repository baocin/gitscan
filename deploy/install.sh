#!/bin/bash
set -e

# git.vet Ubuntu Installation Script
# Run as root on Ubuntu 22.04+ server
#
# This script:
# - Creates a 'gitvet' system user with home directory (/home/gitvet)
# - Installs dependencies (Go, Python, opengrep/semgrep)
# - Builds the git-vet-server binary
# - Sets up systemd service
# - Configures proper permissions for:
#   - User home directory
#   - Application binary (/opt/gitvet/git-vet-server)
#   - Cache and data directories (/var/lib/gitvet)
#   - Access to opengrep/semgrep scanner

echo "=== git.vet Deployment ==="

# Install dependencies
apt-get update
apt-get install -y git golang-go python3 python3-pip || true
apt-get install -y cloudflared || true

# Install OpenGrep 1.15.1 if not already present
OPENGREP_VERSION="1.15.1"
if ! command -v opengrep &> /dev/null || [ "$(opengrep --version 2>/dev/null)" != "$OPENGREP_VERSION" ]; then
    echo "Installing OpenGrep $OPENGREP_VERSION..."
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_aarch64"
    else
        OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86"
    fi
    wget -O /usr/local/bin/opengrep "$OPENGREP_URL"
    chmod +x /usr/local/bin/opengrep
    echo "OpenGrep $OPENGREP_VERSION installed"
else
    echo "OpenGrep $OPENGREP_VERSION already installed"
fi

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

# Create app user with home directory
if ! id gitvet &>/dev/null; then
    useradd -r -m -d /home/gitvet -s /bin/bash gitvet
    echo "Created user 'gitvet' with home directory /home/gitvet"
else
    echo "User 'gitvet' already exists"
    # Ensure home directory exists
    if [ ! -d /home/gitvet ]; then
        mkdir -p /home/gitvet
        chown gitvet:gitvet /home/gitvet
        chmod 755 /home/gitvet
    fi
fi

# Create directories
mkdir -p /opt/gitvet
mkdir -p /var/lib/gitvet/cache
mkdir -p /var/lib/gitvet/data
mkdir -p /var/lib/gitvet/.semgrep
chown -R gitvet:gitvet /var/lib/gitvet /home/gitvet
chmod 755 /home/gitvet

# Build from source (or copy pre-built binary)
cd /tmp
if [ -d "gitscan" ]; then rm -rf gitscan; fi
git clone https://github.com/baocin/gitscan.git
cd gitscan
go build -o /opt/gitvet/git-vet-server ./cmd/gitscan-server
chown gitvet:gitvet /opt/gitvet/git-vet-server
chmod 755 /opt/gitvet/git-vet-server
echo "Built and installed git-vet-server with execute permissions"

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
Environment="XDG_CACHE_HOME=/var/lib/gitvet/cache"
Environment="XDG_CONFIG_HOME=/var/lib/gitvet"
Environment="SEMGREP_SEND_METRICS=off"
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

# Verify permissions
echo ""
echo "=== Verifying Permissions ==="
echo "Checking gitvet user can execute opengrep..."
if sudo -u gitvet which $SCANNER_PATH &>/dev/null; then
    echo "✓ gitvet user can access $SCANNER_PATH"
else
    echo "✗ WARNING: gitvet user cannot access $SCANNER_PATH"
fi

echo "Checking gitvet user can execute git-vet-server..."
if sudo -u gitvet test -x /opt/gitvet/git-vet-server; then
    echo "✓ gitvet user can execute /opt/gitvet/git-vet-server"
else
    echo "✗ WARNING: gitvet user cannot execute /opt/gitvet/git-vet-server"
fi

echo "Checking home directory permissions..."
if [ -d /home/gitvet ] && [ "$(stat -c '%U' /home/gitvet)" = "gitvet" ]; then
    echo "✓ /home/gitvet exists and is owned by gitvet"
else
    echo "✗ WARNING: /home/gitvet has incorrect ownership"
fi

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
