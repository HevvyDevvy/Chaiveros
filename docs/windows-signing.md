# Windows Kernel Driver Signing

Windows 10/11 with Secure Boot enabled enforces **kernel-mode code signing**.
`Windows-Kernel-Scanner.cpp` must be signed before it will load on a
production system.

## Lab / VM — Test Signing (NOT for production)

Enable test-signing mode in an elevated command prompt:

```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
```

After reboot, load the driver:
```cmd
sc create RwdScanner type= kernel start= demand binPath= C:\path\windows_scanner.sys
sc start RwdScanner
```

Disable when done:
```cmd
bcdedit /set testsigning off
bcdedit /set nointegritychecks off
```

> ⚠️ Test-signing weakens system security. Only use in an isolated lab VM.

## Production — Microsoft Attestation Signing

For a driver that loads on any standard Windows 10/11 machine:

### Step 1 — EV Code Signing Certificate
Purchase an Extended Validation (EV) code-signing certificate from a
Microsoft-trusted CA (DigiCert, Sectigo, GlobalSign).

### Step 2 — Sign the driver package
```powershell
signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 `
  /n "Your Company Name" windows_scanner.sys
```

### Step 3 — Create a Driver Submission Package (.cab)
```cmd
makecab windows_scanner.sys windows_scanner.cab
```

### Step 4 — Submit via Microsoft Partner Center
1. Go to [partner.microsoft.com/dashboard](https://partner.microsoft.com/dashboard).
2. Navigate to **Hardware → Driver signing**.
3. Upload the `.cab` file.
4. Select **Attestation signing**.
5. Download the signed `.sys` from the portal (24–48 h turnaround).

### Step 5 — Deploy
```cmd
pnputil /add-driver windows_scanner.inf /install
```

## WDK Build Environment

Full WDK compilation (not just syntax checking) requires:

1. Install **Visual Studio 2022** (Community or higher)
2. Install the **Windows Driver Kit (WDK)**:
   [learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
3. Open the WDK project in Visual Studio and build normally.

The GitHub Actions CI step performs syntax-only compilation with MSVC.
Full WDK builds are a local step due to WDK licensing.
