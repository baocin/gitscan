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

# Add gitvet user to ssl-cert group for Let's Encrypt certificate access
if getent group ssl-cert &>/dev/null; then
    usermod -a -G ssl-cert gitvet
    echo "Added gitvet to ssl-cert group"
else
    echo "ssl-cert group doesn't exist (will set ACLs directly on certificates)"
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
go build -o /opt/gitvet/gitvet-server ./cmd/gitscan-server
chown gitvet:gitvet /opt/gitvet/gitvet-server
chmod 755 /opt/gitvet/gitvet-server

# Grant capability to bind to privileged ports
if setcap 'cap_net_bind_service=+ep' /opt/gitvet/gitvet-server; then
    CAP_CHECK=$(getcap /opt/gitvet/gitvet-server 2>/dev/null)
    echo "Built and installed gitvet-server with execute permissions"
    echo "Capability set: $CAP_CHECK"
else
    echo "ERROR: Failed to set capability for privileged ports!"
    echo "Run manually: sudo setcap 'cap_net_bind_service=+ep' /opt/gitvet/gitvet-server"
    exit 1
fi

# Install deployment scripts for future updates
mkdir -p /opt/gitvet/scripts
cp deploy/update.sh /opt/gitvet/scripts/update.sh
cp deploy/reset_cache.sh /opt/gitvet/scripts/reset_cache.sh
chmod 755 /opt/gitvet/scripts/update.sh
chmod 755 /opt/gitvet/scripts/reset_cache.sh
echo "Installed deployment scripts to /opt/gitvet/scripts/"

# Install systemd service (note: EOF without quotes to allow variable expansion)
cat > /etc/systemd/system/gitvet.service << EOF
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
ExecStart=/opt/gitvet/gitvet-server \
    -listen 0.0.0.0:80 \
    -tls-listen 0.0.0.0:443 \
    -tls-cert /etc/letsencrypt/live/git.vet/fullchain.pem \
    -tls-key /etc/letsencrypt/live/git.vet/privkey.pem \
    -ssh-listen 0.0.0.0:22 \
    -enable-ssh=true \
    -db /var/lib/gitvet/data/gitvet.db \
    -cache-dir /var/lib/gitvet/cache \
    -opengrep $SCANNER_PATH \
    -scan-timeout 300 \
    -reset-db=false
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

echo "Checking gitvet user can execute gitvet-server..."
if sudo -u gitvet test -x /opt/gitvet/gitvet-server; then
    echo "✓ gitvet user can execute /opt/gitvet/gitvet-server"
else
    echo "✗ WARNING: gitvet user cannot execute /opt/gitvet/gitvet-server"
fi

echo "Checking home directory permissions..."
if [ -d /home/gitvet ] && [ "$(stat -c '%U' /home/gitvet)" = "gitvet" ]; then
    echo "✓ /home/gitvet exists and is owned by gitvet"
else
    echo "✗ WARNING: /home/gitvet has incorrect ownership"
fi

# Set up certificate permissions (if certificates exist)
if [ -d /etc/letsencrypt/live ]; then
    echo "Configuring Let's Encrypt certificate permissions..."
    # Try using setfacl first (preferred method)
    if command -v setfacl &>/dev/null; then
        setfacl -R -m u:gitvet:rX /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
        echo "✓ Set ACLs on Let's Encrypt certificates for gitvet user"
    else
        # Fallback: add to ssl-cert group and set group permissions
        chgrp -R ssl-cert /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
        chmod -R g+rX /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
        echo "✓ Set group permissions on Let's Encrypt certificates"
    fi
else
    echo "⚠ Let's Encrypt certificates not found - will need to configure after obtaining certificates"
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
echo "git.vet is running on:"
echo "  HTTP:  http://localhost:80"
echo "  HTTPS: https://git.vet (port 443)"
echo "  SSH:   ssh://git.vet (port 22)"
echo ""
echo "Management commands:"
echo "  Update:       sudo /opt/gitvet/scripts/update.sh"
echo "  Reset cache:  sudo /opt/gitvet/scripts/reset_cache.sh"
echo "  View logs:    journalctl -u gitvet -f"
echo ""
echo "Database management:"
echo "  Location:     /var/lib/gitvet/data/gitvet.db"
echo "  Persistence:  Database persists across restarts (scan history preserved)"
echo "  Manual reset: sudo rm /var/lib/gitvet/data/gitvet.db && sudo systemctl restart gitvet"
echo ""
echo "SSL/TLS certificates:"
echo "  Get certificate: sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/cloudflare.ini -d git.vet"
echo "  Renew:           sudo certbot renew"
echo "  Location:        /etc/letsencrypt/live/git.vet/"
echo "  After obtaining: sudo setfacl -R -m u:gitvet:rX /etc/letsencrypt/live /etc/letsencrypt/archive"
echo ""
echo "Next steps:"
echo "1. Get Let's Encrypt certificate (DNS challenge):"
echo "   sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/cloudflare.ini -d git.vet"
echo "2. Set certificate permissions:"
echo "   sudo setfacl -R -m u:gitvet:rX /etc/letsencrypt/live /etc/letsencrypt/archive"
echo "3. Restart service: sudo systemctl restart gitvet"
echo "4. Test HTTP:  curl http://localhost:80/github.com/baocin/gitscan"
echo "5. Test HTTPS: curl https://git.vet/github.com/baocin/gitscan"
echo "6. Test SSH:   git clone ssh://git.vet/github.com/baocin/gitscan"
echo ""
