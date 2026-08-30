import { EventEmitter } from 'events'
import { FridaScanner }    from './frida-hooks.js'
import { PacketScanner }   from './packet-capture.js'
import { ProcessScanner }  from './process-monitor.js'
import { KernelManager }   from './kernel-manager.js'

/**
 * ScannerOrchestrator
 *
 * Owns all four scanner sub-systems and provides a single unified
 * interface. Events are logged via secureLog and forwarded to the
 * renderer via the onEvent / onAlert callbacks.
 */
export class ScannerOrchestrator extends EventEmitter {
  constructor({ store, secureLog, privileges, onEvent, onAlert }) {
    super()
    this.store       = store
    this.secureLog   = secureLog
    this.privileges  = privileges
    this.onEvent     = onEvent
    this.onAlert     = onAlert

    this._running    = false
    this._alertCount = 0
    this._threshold  = store.get('alertThreshold', 5)

    // Instantiate sub-scanners
    this.frida   = new FridaScanner(  (e) => this._handleEvent(e))
    this.packet  = new PacketScanner( (e) => this._handleEvent(e), privileges)
    this.process = new ProcessScanner((e) => this._handleEvent(e), privileges)
    this.kernel  = new KernelManager( (e) => this._handleEvent(e), privileges)
  }

  // ── Lifecycle ────────────────────────────────────────────────────────

  async startAll() {
    if (this._running) return
    const cfg = this.store.store
    const results = {}

    if (cfg.monitorLibraries) {
      results.frida = await this.frida.start().catch(e => ({ error: e.message }))
    }
    if (cfg.monitorPackets && this.privileges.canSniff) {
      results.packet = await this.packet.start(cfg.networkInterface).catch(e => ({ error: e.message }))
    }
    if (cfg.monitorMemory && this.privileges.canReadMemory) {
      results.process = await this.process.start().catch(e => ({ error: e.message }))
    }
    if (cfg.monitorKernel && this.privileges.isElevated) {
      results.kernel = await this.kernel.load().catch(e => ({ error: e.message }))
    }

    this._running = true
    this.emit('started', results)

    await this.secureLog.write({
      type: 'SYSTEM',
      severity: 'INFO',
      data: { message: 'Scanner started', components: results }
    })

    return results
  }

  async stopAll() {
    if (!this._running) return
    await Promise.allSettled([
      this.frida.stop(),
      this.packet.stop(),
      this.process.stop(),
      this.kernel.unload()
    ])
    this._running = false
    this.emit('stopped')

    await this.secureLog.write({
      type: 'SYSTEM',
      severity: 'INFO',
      data: { message: 'Scanner stopped' }
    })
  }

  // ── Event handling ───────────────────────────────────────────────────

  async _handleEvent(event) {
    // Tag with timestamp if not already present
    const enriched = {
      ...event,
      ts: event.ts || new Date().toISOString(),
      id: crypto.randomUUID()
    }

    // Write to secure log (non-blocking)
    this.secureLog.write(enriched).catch(console.error)

    // Forward to renderer
    this.onEvent(enriched)

    // Alert threshold tracking
    if (enriched.severity === 'ALERT' || enriched.type === 'KEY_INTERCEPTED') {
      this._alertCount++
      if (this._alertCount >= this._threshold) {
        const alert = {
          type: 'THRESHOLD_BREACH',
          severity: 'ALERT',
          ts: new Date().toISOString(),
          data: {
            count: this._alertCount,
            threshold: this._threshold,
            message: `${this._alertCount} key events detected — threshold exceeded`
          }
        }
        this.onAlert(alert)
        this._alertCount = 0  // reset after firing
      }
    }
  }

  // ── Controls ─────────────────────────────────────────────────────────

  setAlertThreshold(n) {
    this._threshold = n
    this.kernel.setThreshold(n)
  }

  setInterface(iface) {
    this.packet.setInterface(iface)
  }

  getStatus() {
    return {
      running:   this._running,
      scanners: {
        frida:   this.frida.isRunning(),
        packet:  this.packet.isRunning(),
        process: this.process.isRunning(),
        kernel:  this.kernel.isLoaded()
      },
      alertCount: this._alertCount,
      threshold:  this._threshold
    }
  }

  getPrivileges() {
    return this.privileges
  }
}
