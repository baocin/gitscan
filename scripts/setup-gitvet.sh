#!/bin/bash
#
# GitVet Server Setup Script
# Sets up Ubuntu server for running git.vet security scanner
#
set -e

# Configuration
GITVET_USER="gitvetuser"
GITVET_HOME="/home/${GITVET_USER}"
GITVET_DATA="/var/lib/gitvet"
GITVET_BIN="/opt/gitvet"
OPENGREP_VERSION="1.15.1"

echo "=== GitVet Server Setup ==="
echo "User: ${GITVET_USER}"
echo "Home: ${GITVET_HOME}"
echo "Data: ${GITVET_DATA}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

# 1. Create gitvet user
echo "[1/7] Creating user ${GITVET_USER}..."
if id "${GITVET_USER}" &>/dev/null; then
    echo "  User ${GITVET_USER} already exists"
else
    useradd --system --create-home --home-dir "${GITVET_HOME}" --shell /bin/false "${GITVET_USER}"
    echo "  Created user ${GITVET_USER}"
fi

# 2. Set up home directory structure
echo "[2/7] Setting up home directory..."
mkdir -p "${GITVET_HOME}/.cache/opengrep/v${OPENGREP_VERSION}"
mkdir -p "${GITVET_HOME}/.semgrep"
mkdir -p "${GITVET_HOME}/.config"
chown -R "${GITVET_USER}:${GITVET_USER}" "${GITVET_HOME}"
chmod 755 "${GITVET_HOME}"
echo "  Created ${GITVET_HOME}/.cache/opengrep/v${OPENGREP_VERSION}"

# 3. Set up data directories
echo "[3/7] Setting up data directories..."
mkdir -p "${GITVET_DATA}/data"
mkdir -p "${GITVET_DATA}/cache"
chown -R "${GITVET_USER}:${GITVET_USER}" "${GITVET_DATA}"
chmod 755 "${GITVET_DATA}"
echo "  Created ${GITVET_DATA}"

# 4. Set up binary directory
echo "[4/7] Setting up binary directory..."
mkdir -p "${GITVET_BIN}"
echo "  Created ${GITVET_BIN}"

# 5. Check for opengrep
echo "[5/7] Checking for opengrep..."
if command -v opengrep &>/dev/null; then
    OPENGREP_PATH=$(which opengrep)
    echo "  Found opengrep at ${OPENGREP_PATH}"
elif [ -x "/usr/local/bin/opengrep" ]; then
    OPENGREP_PATH="/usr/local/bin/opengrep"
    echo "  Found opengrep at ${OPENGREP_PATH}"
else
    echo "  WARNING: opengrep not found!"
    echo "  Install opengrep from https://opengrep.dev"
    OPENGREP_PATH="/usr/local/bin/opengrep"
fi

# 6. Create systemd service
echo "[6/7] Creating systemd service..."
cat > /etc/systemd/system/gitvet.service << EOF
[Unit]
Description=git.vet Security Scanner
After=network.target

[Service]
Type=simple
User=${GITVET_USER}
Group=${GITVET_USER}
WorkingDirectory=${GITVET_DATA}
Environment="HOME=${GITVET_HOME}"
Environment="QT_QPA_PLATFORM=offscreen"
ExecStart=${GITVET_BIN}/git-vet-server \\
    -listen :6633 \\
    -db ${GITVET_DATA}/data/gitvet.db \\
    -cache-dir ${GITVET_DATA}/cache \\
    -opengrep ${OPENGREP_PATH}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=git-vet-server

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${GITVET_DATA} ${GITVET_HOME}/.cache ${GITVET_HOME}/.semgrep
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
echo "  Created /etc/systemd/system/gitvet.service"

# Reload systemd
systemctl daemon-reload

# 7. Test opengrep as gitvet user
echo "[7/7] Testing opengrep as ${GITVET_USER}..."
if [ -x "${OPENGREP_PATH}" ]; then
    # Create a test file
    TEST_DIR=$(mktemp -d)
    echo 'eval(user_input)' > "${TEST_DIR}/test.py"
    chown -R "${GITVET_USER}:${GITVET_USER}" "${TEST_DIR}"

    # Run test
    if sudo -u "${GITVET_USER}" "${OPENGREP_PATH}" scan --sarif --config auto "${TEST_DIR}" &>/dev/null; then
        echo "  opengrep test PASSED"
    else
        echo "  opengrep test FAILED - check permissions"
        echo "  Try running: sudo -u ${GITVET_USER} ${OPENGREP_PATH} --version"
    fi
    rm -rf "${TEST_DIR}"
else
    echo "  Skipping test - opengrep not installed"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Build the server binary:"
echo "     go build -o git-vet-server ./cmd/gitscan-server"
echo ""
echo "  2. Install the binary:"
echo "     sudo cp git-vet-server ${GITVET_BIN}/"
echo ""
echo "  3. Start the service:"
echo "     sudo systemctl enable gitvet"
echo "     sudo systemctl start gitvet"
echo ""
echo "  4. Check status:"
echo "     sudo systemctl status gitvet"
echo "     sudo journalctl -u gitvet -f"
echo ""
