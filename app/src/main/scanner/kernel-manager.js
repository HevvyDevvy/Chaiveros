import { spawn, execSync } from 'child_process'
import { join } from 'path'
import { existsSync, createReadStream } from 'fs'
import { platform } from 'os'
import { app } from 'electron'
import readline from 'readline'

const OS = platform()

/**
 * KernelManager
 *
 * Manages the lifecycle of the compiled kernel-level scanner:
 *   Linux   → encryption_scanner.ko (insmod/rmmod)
 *   macOS   → mac_kernel_scanner (kext — legacy, SIP must be off)
 *   Windows → windows_scanner.sys (sc.exe — requires test-signing or attestation)
 *
 * The kernel module writes events to:
 *   Linux   → /dev/kmsg (read via `dmesg -w`)
 *   macOS   → /var/log/system.log
 *   Windows → Windows Event Log
 *
 * Kernel resources are bundled in the Electron app at:
 *   app.getAppPath()/resources/kernel/
 */
export class KernelManager {
  constructor(onEvent, privileges) {
    this.onEvent     = onEvent
    this.privileges  = privileges
    this._loaded     = false
    this._tail       = null    // child process tailing kernel output
    this._threshold  = 5
    this._kernelDir  = join(app.getAppPath(), '..', 'resources', 'kernel')
  }

  // ── Load ─────────────────────────────────────────────────────────────

  async load() {
    if (this._loaded) return
    if (!this.privileges.isElevated) {
      this.onEvent({
        type: 'SYSTEM',
        severity: 'WARNING',
        data: { message: 'Kernel module skipped — app not running as root/admin' }
      })
      return
    }

    switch (OS) {
      case 'linux':   await this._loadLinux();   break
      case 'darwin':  await this._loadMac();     break
      case 'win32':   await this._loadWindows(); break
    }
  }

  // ── Unload ───────────────────────────────────────────────────────────

  async unload() {
    if (!this._loaded) return
    this._tail?.kill()
    this._tail = null

    try {
      switch (OS) {
        case 'linux':
          execSync('rmmod encryption_scanner', { stdio: 'ignore' })
          break
        case 'darwin':
          execSync('kextunload mac_kernel_scanner.kext', { stdio: 'ignore', cwd: this._kernelDir })
          break
        case 'win32':
          execSync('sc stop RwdScanner', { stdio: 'ignore' })
          execSync('sc delete RwdScanner', { stdio: 'ignore' })
          break
      }
    } catch {
      // Best effort — OS may have already cleaned up
    }

    this._loaded = false
  }

  isLoaded()    { return this._loaded }
  setThreshold(n) { this._threshold = n }

  // ── Linux ─────────────────────────────────────────────────────────────

  async _loadLinux() {
    const koPath = join(this._kernelDir, 'linux', 'encryption_scanner.ko')
    if (!existsSync(koPath)) {
      this.onEvent({
        type: 'SYSTEM',
        severity: 'WARNING',
        data: { message: `Kernel module not found at ${koPath} — skipping` }
      })
      return
    }

    try {
      execSync(`insmod "${koPath}"`, { stdio: 'pipe' })
    } catch (err) {
      // Module may already be loaded
      if (!err.stderr?.toString().includes('File exists')) throw err
    }

    this._loaded = true
    this._tailLinuxKmsg()

    this.onEvent({
      type: 'SYSTEM',
      severity: 'INFO',
      data: { message: 'Linux kernel module loaded — tailing /dev/kmsg' }
    })
  }

  _tailLinuxKmsg() {
    // `dmesg -w` streams new kernel messages in real time
    this._tail = spawn('dmesg', ['-w', '--notime'], { stdio: ['ignore', 'pipe', 'ignore'] })

    const rl = readline.createInterface({ input: this._tail.stdout })
    rl.on('line', (line) => {
      if (!line.includes('[RWD]')) return
      // Expected format: [RWD] KEY_EVENT pid=1234 algo=AES-256 key=<hex>
      const match = line.match(/\[RWD\]\s+KEY_EVENT\s+pid=(\d+)\s+algo=(\S+)\s+key=([0-9a-f]+)/i)
      if (match) {
        this.onEvent({
          type: 'KERNEL_KEY_EVENT',
          severity: 'ALERT',
          data: {
            pid: parseInt(match[1]),
            algorithm: match[2],
            keyHex: match[3],
            source: 'kernel-module',
            raw: line.trim()
          }
        })
      }
    })
  }

  // ── macOS ─────────────────────────────────────────────────────────────

  async _loadMac() {
    const kextPath = join(this._kernelDir, 'macos', 'mac_kernel_scanner.kext')
    if (!existsSync(kextPath)) {
      this.onEvent({
        type: 'SYSTEM',
        severity: 'WARNING',
        data: { message: 'macOS kext not found — skipping. See docs/macos-compat.md' }
      })
      return
    }

    try {
      execSync(`kextload "${kextPath}"`, { stdio: 'pipe' })
      this._loaded = true
      this._tailMacLog()
      this.onEvent({
        type: 'SYSTEM',
        severity: 'INFO',
        data: { message: 'macOS kext loaded (SIP must be disabled)' }
      })
    } catch (err) {
      this.onEvent({
        type: 'SYSTEM',
        severity: 'WARNING',
        data: {
          message: 'macOS kext load failed — SIP likely enabled',
          detail: err.stderr?.toString().trim(),
          hint: 'See docs/macos-compat.md for SIP disable procedure or DriverKit port status'
        }
      })
    }
  }

  _tailMacLog() {
    this._tail = spawn('log', ['stream', '--predicate', 'subsystem == "com.rwd.scanner"'], {
      stdio: ['ignore', 'pipe', 'ignore']
    })
    const rl = readline.createInterface({ input: this._tail.stdout })
    rl.on('line', (line) => {
      if (line.includes('[RWD]')) {
        this.onEvent({
          type: 'KERNEL_KEY_EVENT',
          severity: 'ALERT',
          data: { source: 'macos-kext', raw: line.trim() }
        })
      }
    })
  }

  // ── Windows ───────────────────────────────────────────────────────────

  async _loadWindows() {
    const sysPath = join(this._kernelDir, 'windows', 'windows_scanner.sys')
    if (!existsSync(sysPath)) {
      this.onEvent({
        type: 'SYSTEM',
        severity: 'WARNING',
        data: {
          message: 'Windows driver not found — skipping. See docs/windows-signing.md',
          hint: 'Driver requires attestation signing. Enable test-signing in lab VMs.'
        }
      })
      return
    }

    try {
      execSync(`sc create RwdScanner type= kernel start= demand binPath= "${sysPath}"`, { stdio: 'pipe' })
      execSync('sc start RwdScanner', { stdio: 'pipe' })
      this._loaded = true
      this._tailWindowsEventLog()
      this.onEvent({
        type: 'SYSTEM',
        severity: 'INFO',
        data: { message: 'Windows kernel driver loaded' }
      })
    } catch (err) {
      this.onEvent({
        type: 'SYSTEM',
        severity: 'WARNING',
        data: {
          message: 'Windows driver load failed — likely not signed for this system',
          detail: err.stderr?.toString().trim()
        }
      })
    }
  }

  _tailWindowsEventLog() {
    // Poll Windows Event Log for driver events
    this._tail = setInterval(() => {
      try {
        const out = execSync(
          'powershell -command "Get-EventLog -LogName System -Source RwdScanner -Newest 10 | ConvertTo-Json"',
          { stdio: 'pipe', timeout: 5000 }
        ).toString()
        const events = JSON.parse(out)
        const arr = Array.isArray(events) ? events : [events]
        for (const ev of arr) {
          this.onEvent({
            type: 'KERNEL_KEY_EVENT',
            severity: 'ALERT',
            data: { source: 'windows-driver', raw: ev.Message, eventId: ev.EventID }
          })
        }
      } catch {
        // No new events — normal
      }
    }, 2000)
  }
}
