#Requires -RunAsAdministrator
# install-windows.ps1 — Ransomware Defense installer for Windows
# Run in an elevated PowerShell:  .\scripts\install-windows.ps1
param(
    [string]$InstallDir = "C:\Program Files\RansomwareDefense",
    [string]$ConfigDir  = "C:\ProgramData\RansomwareDefense"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Ransomware Defense — Windows Installer ===" -ForegroundColor Cyan
Write-Host ""

# ── Windows version check ─────────────────────
$WinVer = [System.Environment]::OSVersion.Version
Write-Host "Detected Windows $($WinVer.Major).$($WinVer.Minor)"

Write-Host @"

⚠  IMPORTANT — Windows Kernel Driver Signing
   Windows 10/11 with Secure Boot requires kernel drivers to be
   signed with an EV code-signing certificate AND submitted to
   Microsoft's Hardware Dev Center for attestation signing.

   Without attestation signing the driver will not load on a
   standard Windows install.

   Options:
   a) Enable test-signing (lab/VM only):
      bcdedit /set testsigning on  (then reboot)
   b) Purchase an EV certificate and submit via Partner Center.
   c) Use the Python-only scripts — no kernel driver required.

   See docs\windows-signing.md for the full signing workflow.

"@ -ForegroundColor Yellow

$choice = Read-Host "Continue with Python-only install? [Y/n]"
if ($choice -ne "" -and $choice -ne "Y" -and $choice -ne "y") { exit 0 }

# ── Python check ──────────────────────────────
Write-Host "[1/4] Checking Python..."
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "  Python not found. Install from https://python.org then re-run." -ForegroundColor Red
    exit 1
}
$pyVer = python --version
Write-Host "  Found: $pyVer"

# ── Npcap check (for scapy packet capture) ────
Write-Host "[2/4] Checking Npcap (required for network sniffing)..."
if (-not (Test-Path "C:\Windows\System32\Npcap\wpcap.dll")) {
    Write-Host "  Npcap not found. Download from https://npcap.com and install." -ForegroundColor Yellow
    Write-Host "  Scapy network capture will not work without it."
} else {
    Write-Host "  Npcap found."
}

# ── Directories & config ──────────────────────
Write-Host "[3/4] Creating directories and copying files..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir  | Out-Null
New-Item -ItemType Directory -Force -Path "$ConfigDir\logs" | Out-Null

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir

Copy-Item "$repoRoot\*.py"          -Destination $InstallDir -Force
Copy-Item "$repoRoot\config_loader.py" -Destination $InstallDir -Force

$configDest = "$ConfigDir\config.yaml"
if (-not (Test-Path $configDest)) {
    Copy-Item "$repoRoot\config\config.yaml.example" -Destination $configDest
    Write-Host "  ➜ Config template copied to $configDest"
    Write-Host "  ⚠  Edit the file and set your CISO IP before running." -ForegroundColor Yellow
} else {
    Write-Host "  ➜ Existing config.yaml preserved."
}

# ── Python dependencies ───────────────────────
Write-Host "[4/4] Installing Python packages..."
pip install --quiet -r "$repoRoot\requirements.txt"

Write-Host ""
Write-Host "=== Installation complete ===" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. Edit $configDest"
Write-Host "     Set ciso_ip and ciso_port to your CISO machine."
Write-Host "  2. On CISO machine:  python $InstallDir\Listen-In.py"
Write-Host "  3. On this machine (elevated):  python $InstallDir\ChaveirosV3.py"
Write-Host "  4. See docs\windows-signing.md for the kernel driver signing guide."
