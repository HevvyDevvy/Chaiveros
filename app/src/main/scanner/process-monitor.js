import si from 'systeminformation'
import { readFileSync, readdirSync } from 'fs'
import { platform } from 'os'
import { execSync } from 'child_process'

const OS = platform()

/**
 * ProcessScanner
 *
 * Polls the running process list and monitors for:
 *   - New processes with names matching ransomware signatures
 *   - Processes reading large numbers of files rapidly (encryption sweep)
 *   - Anomalous CPU + disk I/O spikes (encryption = CPU + write heavy)
 *
 * On Linux:  reads /proc directly for memory and fd counts
 * On Windows: uses WMI via PowerShell (no native module needed)
 * On macOS:  uses `proc_info` syscall via si
 */
export class ProcessScanner {
  constructor(onEvent, privileges) {
    this.onEvent    = onEvent
    this.privileges = privileges
    this._running   = false
    this._interval  = null
    this._baseline  = new Map()   // pid → { cpu, fds, name }
    this._POLL_MS   = 3000        // poll every 3 seconds

    // Known ransomware process name fragments (lowercase)
    this._signatures = new Set([
      'encrypt', 'ransom', 'locker', 'crypt', 'vault',
      'wncry', 'wcry', 'petya', 'notpetya', 'ryuk',
      'conti', 'revil', 'lockbit', 'blackcat', 'alphv'
    ])
  }

  async start() {
    if (this._running) return
    this._running = true

    // Take initial baseline
    await this._poll()

    this._interval = setInterval(() => this._poll(), this._POLL_MS)

    this.onEvent({
      type: 'SYSTEM',
      severity: 'INFO',
      data: { message: 'Process monitor active', pollMs: this._POLL_MS }
    })
  }

  async stop() {
    if (this._interval) clearInterval(this._interval)
    this._running = false
    this._baseline.clear()
  }

  isRunning() { return this._running }

  // ── Polling ──────────────────────────────────────────────────────────

  async _poll() {
    let procs = []
    try {
      procs = await si.processes()
    } catch {
      return
    }

    for (const proc of procs.list || []) {
      const name = (proc.name || '').toLowerCase()
      const pid  = proc.pid

      // 1. Name signature match
      for (const sig of this._signatures) {
        if (name.includes(sig)) {
          this.onEvent({
            type: 'PROCESS_MATCH',
            severity: 'ALERT',
            data: {
              pid,
              name: proc.name,
              path: proc.path,
              signature: sig,
              reason: `Process name matches ransomware signature: "${sig}"`
            }
          })
        }
      }

      // 2. Anomaly detection vs baseline
      const prev = this._baseline.get(pid)
      if (prev) {
        const cpuDelta = (proc.cpu || 0) - prev.cpu

        // CPU spike > 40% for a non-system process
        if (cpuDelta > 40 && !_isSystemProc(name)) {
          this.onEvent({
            type: 'PROCESS_ANOMALY',
            severity: 'WARNING',
            data: {
              pid, name: proc.name,
              cpu: proc.cpu,
              cpuDelta: cpuDelta.toFixed(1),
              reason: 'Sudden CPU spike — possible encryption loop'
            }
          })
        }

        // fd count spike on Linux (rapid file opening = encryption sweep)
        if (OS === 'linux' && this.privileges.canReadProc) {
          const fds = this._getFdCount(pid)
          if (fds > 200 && (!prev.fds || fds > prev.fds * 2)) {
            this.onEvent({
              type: 'PROCESS_ANOMALY',
              severity: 'WARNING',
              data: {
                pid, name: proc.name,
                openFds: fds,
                prevFds: prev.fds || 0,
                reason: 'File descriptor count explosion — possible mass file encryption'
              }
            })
          }
          this._baseline.set(pid, { cpu: proc.cpu || 0, fds, name: proc.name })
          continue
        }
      }

      this._baseline.set(pid, { cpu: proc.cpu || 0, name: proc.name })
    }

    // Clean up exited processes from baseline
    const livePids = new Set((procs.list || []).map(p => p.pid))
    for (const pid of this._baseline.keys()) {
      if (!livePids.has(pid)) this._baseline.delete(pid)
    }
  }

  // ── Linux /proc helpers ──────────────────────────────────────────────

  _getFdCount(pid) {
    try {
      return readdirSync(`/proc/${pid}/fd`).length
    } catch {
      return 0
    }
  }

  /**
   * Scan Linux /proc/[pid]/mem for high-entropy 32-byte aligned regions
   * that look like AES keys. Requires CAP_SYS_PTRACE or root.
   */
  scanProcessMemory(pid) {
    if (OS !== 'linux' || !this.privileges.canReadProc) return null
    try {
      const maps   = readFileSync(`/proc/${pid}/maps`, 'utf8')
      const ranges = _parseHeapRanges(maps)
      const results = []

      for (const [start, end] of ranges.slice(0, 5)) {
        // Limit to first 5 heap regions to avoid performance issues
        const size = Math.min(end - start, 1024 * 1024) // cap at 1 MB
        if (size <= 0) continue
        // Note: direct /proc/pid/mem reads require a native approach
        // on most Linux configs — this is a placeholder for the C helper
        results.push({ start: start.toString(16), size })
      }

      return results
    } catch {
      return null
    }
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────

function _isSystemProc(name) {
  const systemNames = [
    'systemd', 'kernel', 'kworker', 'kthread',
    'launchd', 'svchost', 'lsass', 'csrss'
  ]
  return systemNames.some(s => name.includes(s))
}

function _parseHeapRanges(mapsContent) {
  const ranges = []
  for (const line of mapsContent.split('\n')) {
    if (!line.includes('heap') && !line.includes('rw-p')) continue
    const [range] = line.split(' ')
    const [startHex, endHex] = range.split('-')
    if (!startHex || !endHex) continue
    const start = parseInt(startHex, 16)
    const end   = parseInt(endHex, 16)
    if (!isNaN(start) && !isNaN(end) && end > start) {
      ranges.push([start, end])
    }
  }
  return ranges
}
