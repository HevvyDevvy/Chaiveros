import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import os from 'os'

/**
 * RecoveryEngine
 *
 * Decrypts files using a key captured by FridaScanner (KEY_INTERCEPTED events).
 * Three escalating scopes, same engine underneath:
 *
 *   'file'      — one specific file
 *   'directory' — a folder, recursive
 *   'system'    — every fixed drive / the whole filesystem, with hard
 *                 exclusions for OS and program directories
 *
 * Safety model (this is the part that matters more than the decryption math):
 *   1. Nothing is ever overwritten blind. Before touching a file, its
 *      original bytes are copied into a quarantine folder, preserving the
 *      original path. This is what makes "Undo last recovery" possible.
 *   2. Every run starts as a dry run (previewScope) that just counts and
 *      classifies files — nothing is written until the caller explicitly
 *      calls run() with confirm: true.
 *   3. A fixed deny-list of OS/program paths is never touched, even under
 *      'system' scope, unless the caller passes allowSystemPaths: true
 *      (and even then, a smaller hard-coded "never touch" set remains).
 *   4. Executables and other binary formats that are almost never what
 *      ransomware encrypts (and are catastrophic to corrupt) are skipped
 *      by default — .exe, .dll, .sys, .so, .dylib — unless explicitly
 *      included.
 */

const DEFAULT_SKIP_EXT = new Set(['.exe', '.dll', '.sys', '.so', '.dylib', '.msi'])

const HARD_DENY_ALWAYS = process.platform === 'win32'
  ? [
      'C:\\Windows',
      'C:\\Program Files',
      'C:\\Program Files (x86)',
      'C:\\ProgramData\\Microsoft'
    ]
  : [
      '/System', '/usr', '/bin', '/sbin', '/lib', '/lib64',
      '/boot', '/etc', '/proc', '/sys', '/dev'
    ]

function isUnderAny(target, dirs) {
  const norm = path.resolve(target)
  return dirs.some(d => {
    const nd = path.resolve(d)
    return norm === nd || norm.startsWith(nd + path.sep)
  })
}

export class RecoveryEngine {
  constructor({ secureLog, quarantineDir } = {}) {
    this.secureLog = secureLog
    this.quarantineDir = quarantineDir || path.join(os.homedir(), '.chaiveros', 'quarantine')
    this._lastRun = null // for undo
  }

  // ── Enumeration ──────────────────────────────────────────────────────

  _listCandidates(scope, target) {
    let roots
    if (scope === 'file') {
      roots = [target]
      return this._filesOnly(roots)
    }
    if (scope === 'directory') {
      roots = [target]
    } else if (scope === 'system') {
      roots = process.platform === 'win32'
        ? this._windowsFixedDrives()
        : ['/']
    } else {
      throw new Error(`Unknown scope: ${scope}`)
    }

    const out = []
    for (const root of roots) {
      this._walk(root, out)
    }
    return out
  }

  _filesOnly(paths) {
    return paths.filter(p => {
      try { return fs.statSync(p).isFile() } catch { return false }
    })
  }

  _windowsFixedDrives() {
    // Best-effort: try common letters, keep the ones that exist.
    const letters = 'CDEFGH'.split('')
    return letters
      .map(l => `${l}:\\`)
      .filter(d => { try { return fs.existsSync(d) } catch { return false } })
  }

  _walk(dir, out, depth = 0) {
    if (depth > 64) return // guard against symlink cycles
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return // permission denied, gone, etc — skip silently
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name)
      if (isUnderAny(full, HARD_DENY_ALWAYS)) continue
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) {
        this._walk(full, out, depth + 1)
      } else if (entry.isFile()) {
        out.push(full)
      }
    }
  }

  // ── Dry run ──────────────────────────────────────────────────────────

  /**
   * Classify candidate files without touching anything.
   * Returns counts + a capped sample list for the UI to show the user
   * before they confirm.
   */
  previewScope(scope, target, opts = {}) {
    const skipExt = opts.skipExt || DEFAULT_SKIP_EXT
    const candidates = this._listCandidates(scope, target)

    const willAttempt = []
    const skippedBinary = []
    const skippedDenied = []

    for (const f of candidates) {
      const ext = path.extname(f).toLowerCase()
      if (skipExt.has(ext)) {
        skippedBinary.push(f)
        continue
      }
      willAttempt.push(f)
    }

    return {
      scope,
      target,
      totalFound: candidates.length,
      willAttemptCount: willAttempt.length,
      skippedBinaryCount: skippedBinary.length,
      sample: willAttempt.slice(0, 25),
      warning: scope === 'system'
        ? 'System-wide scope. This will attempt every non-excluded file on the ' +
          'machine. Strongly recommend running "directory" scope against the ' +
          'known-affected folder first.'
        : null
    }
  }

  // ── Execution ────────────────────────────────────────────────────────

  /**
   * Run recovery. Requires confirm:true — this is the point of no return
   * (though every original is quarantined first, so it's reversible via undo()).
   *
   * @param {'file'|'directory'|'system'} scope
   * @param {string} target       - file or directory path (ignored for 'system')
   * @param {Buffer} key          - decryption key, from a KEY_INTERCEPTED event
   * @param {string} algorithm    - 'aes-256-cbc' (only supported mode today)
   * @param {object} opts
   */
  async run(scope, target, key, algorithm = 'aes-256-cbc', opts = {}) {
    if (!opts.confirm) {
      throw new Error('run() requires { confirm: true } — call previewScope() first')
    }
    const skipExt = opts.skipExt || DEFAULT_SKIP_EXT
    const runId = crypto.randomUUID()
    const runQuarantineDir = path.join(this.quarantineDir, runId)
    fs.mkdirSync(runQuarantineDir, { recursive: true })

    const candidates = this._listCandidates(scope, target)
    const results = { runId, ok: [], failed: [], skipped: [] }

    for (const filePath of candidates) {
      const ext = path.extname(filePath).toLowerCase()
      if (skipExt.has(ext)) {
        results.skipped.push(filePath)
        continue
      }

      try {
        const original = fs.readFileSync(filePath)
        const decrypted = this._decrypt(original, key, algorithm)

        // Quarantine the original BEFORE overwriting, preserving structure.
        const backupPath = path.join(runQuarantineDir, this._safeRelPath(filePath))
        fs.mkdirSync(path.dirname(backupPath), { recursive: true })
        fs.copyFileSync(filePath, backupPath)

        fs.writeFileSync(filePath, decrypted)
        results.ok.push(filePath)
      } catch (err) {
        results.failed.push({ file: filePath, error: err.message })
      }
    }

    this._lastRun = { runId, quarantineDir: runQuarantineDir, files: results.ok }

    if (this.secureLog) {
      await this.secureLog.write({
        type: 'RECOVERY',
        severity: 'INFO',
        data: {
          scope, target, runId,
          recovered: results.ok.length,
          failed: results.failed.length,
          skipped: results.skipped.length
        }
      }).catch(() => {})
    }

    return results
  }

  /** Restore original (pre-decryption) bytes for the most recent run. */
  async undoLastRun() {
    if (!this._lastRun) throw new Error('No recovery run to undo')
    const { quarantineDir, files } = this._lastRun
    let restored = 0
    for (const filePath of files) {
      const backupPath = path.join(quarantineDir, this._safeRelPath(filePath))
      try {
        fs.copyFileSync(backupPath, filePath)
        restored++
      } catch { /* best-effort */ }
    }
    return { restored, total: files.length }
  }

  // ── Internals ────────────────────────────────────────────────────────

  _safeRelPath(absPath) {
    // Turn an absolute path into a filesystem-safe relative path for the
    // quarantine mirror, e.g. C:\Users\x\a.txt -> C_/Users/x/a.txt
    return absPath.replace(/^([A-Za-z]):[\\/]/, '$1_/').replace(/\\/g, '/')
  }

  _decrypt(buffer, key, algorithm) {
    if (algorithm !== 'aes-256-cbc') {
      throw new Error(`Unsupported algorithm: ${algorithm}`)
    }
    if (!key || key.length !== 32) {
      throw new Error('AES-256 requires a 32-byte key')
    }
    const iv = buffer.subarray(0, 16)
    const ciphertext = buffer.subarray(16)
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  }
}
