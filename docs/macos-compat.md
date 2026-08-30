# macOS Compatibility Notes

## Current State

`Mac-Kernel-Scanner.m` uses the legacy **kernel extension (kext)** API.
Apple deprecated kexts in macOS 11 (Big Sur, 2020) and will remove the
ability to load them in a future release.

| macOS Version | Kext loads? | Workaround |
|---|---|---|
| 10.15 Catalina | ✅ Yes (with SIP approval) | — |
| 11 Big Sur | ⚠️ Legacy kexts allowed with approval | Notarise the kext |
| 12 Monterey | ⚠️ Legacy kexts allowed, deprecation warning | Notarise the kext |
| 13 Ventura+ | ❌ Most kexts blocked | Use System Extension / DriverKit |

## For Lab / VM Use (macOS ≤ 12)

1. Boot into Recovery Mode (`Cmd+R` at startup).
2. Open Terminal → `csrutil disable`
3. Reboot.
4. Load the kext: `sudo kextload mac_kernel_scanner.kext`
5. Check: `kextstat | grep scanner`

Re-enable SIP after the lab: `csrutil enable`

## For Production Use (macOS 13+)

The scanner must be ported to **DriverKit** / **System Extensions**:

- Apple Developer account required.
- Build as a System Extension (`com.apple.system-extension.endpoint-security`).
- Submit for notarisation via `xcrun notarytool`.
- User must approve in **System Settings → Privacy & Security → Security**.

This port is tracked as a future milestone.  Until then, the Python-only
scripts (`ChaveirosV3.py` + `Listen-In.py`) provide equivalent
userspace monitoring on all macOS versions.

## Notarisation (macOS 11/12)

If you have an Apple Developer account and a signed kext:

```bash
xcrun notarytool submit mac_kernel_scanner.kext.zip \
  --apple-id your@email.com \
  --team-id YOURTEAMID \
  --password "@keychain:AC_PASSWORD" \
  --wait
```

Then staple the ticket:
```bash
xcrun stapler staple mac_kernel_scanner.kext
```
