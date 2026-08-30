# CI Setup Guide — Chaveiros GitHub Actions

## What these workflows do

Every push to `main` or `dev`:
- Compiles `Linux-Kernel-Scanner.c` → `encryption_scanner.ko`
- Compiles `Mac-Kernel-Scanner.m` → `mac_kernel_scanner`
- Validates `Windows-Kernel-Scanner.cpp` with MSVC
- Injects compiled outputs into `app/resources/kernel/<os>/`
- Builds the Electron app for all three platforms
- Uploads platform installers as workflow artefacts

Every version tag (`git tag v1.0.0 && git push --tags`):
- Does everything above
- Creates a GitHub Release with all installers attached

---

## Repo structure required

Your repo root must look like this:

```
Ransomeware_Defense/
├── .github/
│   └── workflows/
│       ├── build.yml          ← drop these two files here
│       └── release.yml
│
├── Linux-Kernel-Scanner.c     ← kernel source at root (already there)
├── Mac-Kernel-Scanner.m
├── Windows-Kernel-Scanner.cpp
│
├── app/                       ← Electron app folder
│   ├── package.json
│   ├── electron-builder.yml
│   ├── electron.vite.config.mjs
│   ├── src/
│   └── resources/
│       ├── entitlements.mac.plist
│       ├── entitlements.mac.inherit.plist
│       ├── icons/
│       │   ├── icon.png       ← 512x512 PNG
│       │   ├── icon.icns      ← macOS (use iconutil or electron-icon-maker)
│       │   └── icon.ico       ← Windows
│       └── kernel/            ← CI writes here automatically — do NOT commit
│           ├── linux/
│           ├── macos/
│           └── windows/
│
├── ChaveirosV3.py
├── ... (other Python scripts)
├── LICENSE
└── DISCLAIMER.md
```

---

## GitHub Secrets to add

Go to: **Your repo → Settings → Secrets and variables → Actions → New repository secret**

### Windows code signing (required for signed installer)

| Secret name | Value |
|---|---|
| `WIN_CSC_LINK` | Base64-encoded `.pfx` certificate — **generate this on your local machine only** |
| `WIN_CSC_KEY_PASSWORD` | Your certificate password |

**How to base64-encode your .pfx — do this LOCALLY, never in chat:**

```bash
# Linux / macOS terminal:
base64 -w 0 cert.pfx

# PowerShell:
[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))
```

Copy the output string. Paste it as the `WIN_CSC_LINK` secret value.

### macOS code signing + notarisation (optional — for signed DMG)

| Secret name | Value |
|---|---|
| `CSC_LINK` | Base64-encoded `.p12` Apple Developer certificate |
| `CSC_KEY_PASSWORD` | Certificate password |
| `APPLE_ID` | Your Apple Developer email |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password from appleid.apple.com |
| `APPLE_TEAM_ID` | Your Team ID from developer.apple.com/account |

If these secrets are absent the macOS build still runs — it just produces an unsigned DMG.

---

## Triggering a release

```bash
# Commit and push your changes first
git add .
git commit -m "Release v1.0.0"
git push

# Tag and push the tag — this triggers release.yml
git tag v1.0.0
git push --tags
```

The release workflow will:
1. Run all three OS jobs in parallel
2. Wait for all three to complete
3. Create a GitHub Release named `🛡 Chaveiros — Ransomware Defense v1.0.0`
4. Attach all installers (`.AppImage`, `.deb`, `.dmg`, `.exe`) to the release

---

## Linux kernel module — version mismatch note

The `.ko` compiled in CI runs against the GitHub Actions runner kernel
(currently Ubuntu 22.04, kernel ~5.15.x). If your target machines run a
different kernel, the module won't load.

**Solutions:**
1. The app's `kernel-manager.js` gracefully falls back if the module won't load
2. The source `Linux-Kernel-Scanner.c` is bundled in the app — users can recompile:
   ```bash
   sudo apt install linux-headers-$(uname -r) build-essential
   # Then recompile using the Makefile in the original repo
   ```
3. For enterprise deployment, use DKMS (Makefile target `make dkms-install`)
