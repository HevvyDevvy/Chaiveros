#!/usr/bin/env bash
# install-macos.sh — Ransomware Defense installer for macOS
# Run with:  sudo bash scripts/install-macos.sh
set -euo pipefail

TOOL_NAME="ransomware-defense"
INSTALL_DIR="/usr/local/opt/${TOOL_NAME}"
CONFIG_DIR="/usr/local/etc/${TOOL_NAME}"
LOG_DIR="/usr/local/var/log/${TOOL_NAME}"

echo "=== Ransomware Defense — macOS Installer ==="
echo

# ── macOS version check ───────────────────────
MACOS_VER=$(sw_vers -productVersion | cut -d. -f1)
echo "Detected macOS ${MACOS_VER}"
if [[ "${MACOS_VER}" -ge 11 ]]; then
  echo ""
  echo "⚠️  IMPORTANT — macOS 11+ (Big Sur and later)"
  echo "   Apple deprecated kernel extensions (kexts) in macOS 11."
  echo "   The legacy Mac-Kernel-Scanner (kext) will NOT load under"
  echo "   System Integrity Protection (SIP) on this version."
  echo ""
  echo "   Options:"
  echo "   a) Disable SIP in Recovery Mode (lab/VM only — not for production)"
  echo "   b) Use the Python-only scripts (ChaveirosV3.py + Listen-In.py)"
  echo "   c) Wait for the DriverKit port — tracked in docs/macos-compat.md"
  echo ""
  read -r -p "Continue with Python-only install? [y/N] " REPLY
  [[ "${REPLY,,}" == "y" ]] || exit 0
fi

# ── Privilege check ────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root (sudo bash $0)"
  exit 1
fi

# ── Dependencies ───────────────────────────────
echo "[1/4] Checking Homebrew..."
if ! command -v brew &>/dev/null; then
  echo "  Homebrew not found. Install it from https://brew.sh then re-run."
  exit 1
fi

echo "[2/4] Installing Python dependencies..."
brew install python3 libpcap tcl-tk 2>/dev/null || true
pip3 install --quiet -r "$(dirname "$0")/../requirements.txt"

# ── Directories & config ───────────────────────
echo "[3/4] Creating directories..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}"

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  cp "$(dirname "$0")/../config/config.yaml.example" "${CONFIG_DIR}/config.yaml"
  echo "  ➜ Config template copied to ${CONFIG_DIR}/config.yaml"
  echo "  ⚠  Edit the file and set your CISO IP before running."
else
  echo "  ➜ Existing config.yaml preserved."
fi

# ── Copy Python scripts ───────────────────────
echo "[4/4] Copying scripts..."
cp "$(dirname "$0")/../"*.py "${INSTALL_DIR}/"
cp "$(dirname "$0")/../config_loader.py" "${INSTALL_DIR}/"

echo
echo "=== Installation complete ==="
echo "Next steps:"
echo "  1. Edit ${CONFIG_DIR}/config.yaml — set ciso_ip and ciso_port"
echo "  2. On CISO machine:  python3 ${INSTALL_DIR}/Listen-In.py"
echo "  3. On this machine:  sudo python3 ${INSTALL_DIR}/ChaveirosV3.py"
echo "  4. See docs/macos-compat.md for full macOS compatibility notes."
