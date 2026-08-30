import {
  createCipheriv, createDecipheriv,
  randomBytes, pbkdf2Sync, createHash
} from 'crypto'
import { createWriteStream, createReadStream, existsSync, unlinkSync, statSync } from 'fs'
import { mkdir } from 'fs/promises'
import { dirname } from 'path'

/**
 * SecureLog
 *
 * Encrypted, tamper-evident, append-only log for ransomware defense events.
 *
 * Format: binary file, each entry is:
 *   [4 bytes: uint32 entry length]
 *   [12 bytes: AES-GCM nonce/IV]
 *   [16 bytes: GCM auth tag]
 *   [N bytes:  AES-256-GCM ciphertext of JSON entry]
 *
 * The JSON entry includes a 'prevHash' field linking to the SHA-256 of the
 * previous ciphertext. This creates a tamper-evident chain — modifying any
 * entry breaks all subsequent hashes.
 *
 * Key derivation: PBKDF2-SHA256, 210,000 iterations (NIST recommended 2024),
 * 32-byte output. Salt is stored separately in [logPath].salt (not in the log).
 */

const ALGO           = 'aes-256-gcm'
const IV_LEN         = 12    // bytes
const TAG_LEN        = 16    // bytes
const KEY_LEN        = 32    // bytes (256-bit)
const PBKDF2_ITERS   = 210_000
const PBKDF2_DIGEST  = 'sha256'
const SALT_LEN       = 32    // bytes

export class SecureLog {
  constructor(logPath) {
    this._path      = logPath
    this._saltPath  = logPath + '.salt'
    this._key       = null    // Buffer — null until unlocked
    this._lastHash  = Buffer.alloc(32, 0)  // genesis hash (all zeros)
    this._writeStream = null
    this._queue     = []      // pending writes before unlock
    this._writing   = false
  }

  // ── Unlock / key derivation ──────────────────────────────────────────

  /**
   * Derive the log key from a user passphrase.
   * Creates the salt file on first call, reads it on subsequent calls.
   */
  async unlock(passphrase) {
    if (!passphrase || passphrase.length < 8) {
      throw new Error('Passphrase must be at least 8 characters')
    }

    // Load or generate salt
    let salt
    if (existsSync(this._saltPath)) {
      salt = Buffer.from(
        await import('fs/promises').then(f => f.readFile(this._saltPath))
      )
    } else {
      salt = randomBytes(SALT_LEN)
      await mkdir(dirname(this._saltPath), { recursive: true })
      await import('fs/promises').then(f => f.writeFile(this._saltPath, salt))
    }

    // Derive key (synchronous PBKDF2 — intentionally blocking to deter brute-force)
    this._key = pbkdf2Sync(passphrase, salt, PBKDF2_ITERS, KEY_LEN, PBKDF2_DIGEST)

    // Compute _lastHash from existing log tail (for chain continuity)
    if (existsSync(this._path)) {
      await this._computeLastHash()
    }

    // Open write stream
    await mkdir(dirname(this._path), { recursive: true })
    this._writeStream = createWriteStream(this._path, { flags: 'a' })

    // Flush queued writes
    for (const entry of this._queue) {
      await this._writeEntry(entry)
    }
    this._queue = []

    return true
  }

  isUnlocked() { return this._key !== null }
  getPath()    { return this._path }

  setPath(newPath) {
    this._writeStream?.end()
    this._writeStream = null
    this._path = newPath
    this._saltPath = newPath + '.salt'
    // Re-open stream if already unlocked
    if (this._key) {
      mkdir(dirname(newPath), { recursive: true }).then(() => {
        this._writeStream = createWriteStream(newPath, { flags: 'a' })
      })
    }
  }

  // ── Write ────────────────────────────────────────────────────────────

  async write(event) {
    const entry = {
      ...event,
      ts:       event.ts       || new Date().toISOString(),
      severity: event.severity || 'INFO',
      prevHash: this._lastHash.toString('hex')
    }

    if (!this._key) {
      // Queue until unlocked
      this._queue.push(entry)
      if (this._queue.length > 1000) this._queue.shift() // cap queue size
      return
    }

    await this._writeEntry(entry)
  }

  async _writeEntry(entry) {
    if (!this._key || !this._writeStream) return

    const plaintext = Buffer.from(JSON.stringify(entry), 'utf8')
    const iv        = randomBytes(IV_LEN)
    const cipher    = createCipheriv(ALGO, this._key, iv)

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag       = cipher.getAuthTag()

    // Update chain hash
    this._lastHash = createHash('sha256').update(encrypted).digest()

    // Binary frame: [4B length][12B IV][16B tag][N bytes ciphertext]
    const frameLen = IV_LEN + TAG_LEN + encrypted.length
    const lenBuf   = Buffer.allocUnsafe(4)
    lenBuf.writeUInt32BE(frameLen, 0)

    const frame = Buffer.concat([lenBuf, iv, tag, encrypted])

    await new Promise((resolve, reject) => {
      this._writeStream.write(frame, (err) => err ? reject(err) : resolve())
    })
  }

  // ── Read ─────────────────────────────────────────────────────────────

  async read({ limit = 200, offset = 0, filter = null } = {}) {
    if (!this._key) return { error: 'LOG_LOCKED', entries: [] }
    if (!existsSync(this._path)) return { entries: [], total: 0 }

    const entries  = []
    const errors   = []
    let   prevHash = Buffer.alloc(32, 0)
    let   index    = 0

    const data = await import('fs/promises').then(f => f.readFile(this._path))
    let pos = 0

    while (pos < data.length - 4) {
      try {
        const frameLen  = data.readUInt32BE(pos);          pos += 4
        const iv        = data.slice(pos, pos + IV_LEN);   pos += IV_LEN
        const tag       = data.slice(pos, pos + TAG_LEN);  pos += TAG_LEN
        const encrypted = data.slice(pos, pos + frameLen - IV_LEN - TAG_LEN)
        pos += frameLen - IV_LEN - TAG_LEN

        // Verify chain
        const entryHash = createHash('sha256').update(encrypted).digest()
        const decipher  = createDecipheriv(ALGO, this._key, iv)
        decipher.setAuthTag(tag)

        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()])
        const entry     = JSON.parse(decrypted.toString('utf8'))

        // Chain integrity check
        const chainOK = entry.prevHash === prevHash.toString('hex')
        entry._chainOK = chainOK
        if (!chainOK) entry._chainWarning = 'Hash chain broken — log may have been tampered with'

        prevHash = entryHash
        index++

        if (index <= offset) continue
        if (filter && !_matchesFilter(entry, filter)) continue

        entries.push(entry)
        if (entries.length >= limit) break

      } catch (err) {
        errors.push({ pos, error: err.message })
        // Try to skip to next frame
        pos += 1
      }
    }

    return { entries, total: index, errors }
  }

  // ── Export (decrypted JSON) ───────────────────────────────────────────

  async exportDecrypted(destPath) {
    const { entries, total } = await this.read({ limit: 100_000 })
    await import('fs/promises').then(f =>
      f.writeFile(destPath, JSON.stringify(entries, null, 2), 'utf8')
    )
    return { exported: entries.length, total, destPath }
  }

  // ── Flush & clear ────────────────────────────────────────────────────

  async flush() {
    await new Promise((resolve) => this._writeStream?.end(resolve))
  }

  clear() {
    this._writeStream?.end()
    this._writeStream = null
    if (existsSync(this._path)) unlinkSync(this._path)
    this._lastHash = Buffer.alloc(32, 0)
    if (this._key) {
      this._writeStream = createWriteStream(this._path, { flags: 'a' })
    }
  }

  // ── Chain re-computation ─────────────────────────────────────────────

  async _computeLastHash() {
    const data = await import('fs/promises').then(f => f.readFile(this._path))
    let pos = 0
    let lastHash = Buffer.alloc(32, 0)

    while (pos < data.length - 4) {
      try {
        const frameLen  = data.readUInt32BE(pos);          pos += 4
        pos += IV_LEN + TAG_LEN
        const cipherLen = frameLen - IV_LEN - TAG_LEN
        const encrypted = data.slice(pos, pos + cipherLen); pos += cipherLen
        lastHash = createHash('sha256').update(encrypted).digest()
      } catch { pos++ }
    }

    this._lastHash = lastHash
  }
}

function _matchesFilter(entry, filter) {
  const s = JSON.stringify(entry).toLowerCase()
  return s.includes(filter.toLowerCase())
}
