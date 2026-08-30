#!/usr/bin/env bash
# install-linux.sh — Ransomware Defense installer for Linux
# Run as root:  sudo bash scripts/install-linux.sh
set -euo pipefail

TOOL_NAME="ransomware-defense"
INSTALL_DIR="/opt/${TOOL_NAME}"
CONFIG_DIR="/etc/${TOOL_NAME}"
LOG_DIR="/var/log/${TOOL_NAME}"
SERVICE_USER="rwd"

echo "=== Ransomware Defense — Linux Installer ==="
echo

# ── Privilege check ────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root (sudo bash $0)"
  exit 1
fi

# ── Dependencies ───────────────────────────────
echo "[1/6] Installing system dependencies..."
apt-get update -qq
apt-get install -y \
  python3 python3-pip python3-tk \
  libpcap-dev \
  linux-headers-"$(uname -r)" \
  build-essential make

echo "[2/6] Installing Python packages..."
pip3 install --quiet -r "$(dirname "$0")/../requirements.txt"

# ── Directories & config ───────────────────────
echo "[3/6] Creating directories..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}"

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  cp "$(dirname "$0")/../config/config.yaml.example" "${CONFIG_DIR}/config.yaml"
  echo "  ➜ Config template copied to ${CONFIG_DIR}/config.yaml"
  echo "  ⚠  Edit ${CONFIG_DIR}/config.yaml and set your CISO IP before running."
else
  echo "  ➜ Existing config.yaml preserved."
fi

# ── Copy scripts ───────────────────────────────
echo "[4/6] Copying scripts to ${INSTALL_DIR}..."
cp -r "$(dirname "$0")/../"*.py "${INSTALL_DIR}/"
cp -r "$(dirname "$0")/../config_loader.py" "${INSTALL_DIR}/"
cp -r "$(dirname "$0")/../remote-kernel-log-viewer" "${INSTALL_DIR}/"

# ── Load kernel module ────────────────────────
echo "[5/6] Building and loading kernel module..."
pushd "$(dirname "$0")/.." > /dev/null
make all
if [[ -f encryption_scanner.ko ]]; then
  insmod encryption_scanner.ko || modprobe encryption_scanner || true
  echo "  ➜ Kernel module loaded. Check: dmesg | tail -20"
else
  echo "  ⚠  Kernel module build failed — check Makefile output above."
fi
popd > /dev/null

# ── Systemd service (optional) ────────────────
echo "[6/6] Installing systemd service..."
cat > /etc/systemd/system/chaveiros.service << 'UNIT'
[Unit]
Description=Ransomware Defense — ChaveirosV3 Key Interceptor
After=network.target
Documentation=https://github.com/DeadmanXXXII/Ransomeware_Defense

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/ransomware-defense/ChaveirosV3.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=chaveiros

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
echo "  ➜ Service installed. Enable with: systemctl enable --now chaveiros"

echo
echo "=== Installation complete ==="
echo "Next steps:"
echo "  1. Edit ${CONFIG_DIR}/config.yaml — set ciso_ip and ciso_port"
echo "  2. Start listener on CISO machine:  python3 Listen-In.py"
echo "  3. Start interceptor:  systemctl start chaveiros"
echo "  4. Check logs:  journalctl -u chaveiros -f"
