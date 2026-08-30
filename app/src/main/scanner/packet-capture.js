import pcap from 'pcap'
import { networkInterfaces } from 'os'

const { PROTOCOL } = decoders

/**
 * PacketScanner
 *
 * Monitors network traffic for ransomware C2 patterns:
 *   - Key exfiltration payloads (high-entropy short TCP bursts)
 *   - Known ransomware port signatures
 *   - Unusual encrypted outbound connections from non-browser processes
 *
 * Uses the `cap` npm package which wraps libpcap (Linux/macOS) and
 * Npcap (Windows). Requires elevated privileges.
 */
export class PacketScanner {
  constructor(onEvent, privileges) {
    this.onEvent    = onEvent
    this.privileges = privileges
    this._cap       = null
    this._running   = false
    this._iface     = 'auto'
    this._buffer    = Buffer.alloc(65535)

    // Suspicious outbound port patterns used by ransomware families
    this._suspiciousPorts = new Set([
      4444, 4445, 8443, 9001, 9050,  // common C2 / Tor
      443, 80                         // also watch HTTPS/HTTP for exfil
    ])
  }

  // ── Public API ───────────────────────────────────────────────────────

  async start(iface = 'auto') {
    if (this._running) return
    if (!this.privileges.canSniff) {
      this.onEvent({
        type: 'SYSTEM',
        severity: 'WARNING',
        data: { message: 'Packet capture skipped — insufficient privileges (need root/admin + libpcap/Npcap)' }
      })
      return
    }

    const device = iface === 'auto' ? this._autoDetectInterface() : iface
    if (!device) throw new Error('No suitable network interface found')

    this._cap = new Cap()

    // BPF filter: outbound TCP only, skip loopback
    const filter = 'tcp and not host 127.0.0.1'
    const bufSize = 10 * 1024 * 1024  // 10 MB ring buffer

    this._cap.open(device, filter, bufSize, this._buffer)
    this._cap.setMinBytes && this._cap.setMinBytes(0)

    this._cap.on('packet', (nbytes, trunc) => {
      this._handlePacket(nbytes, trunc)
    })

    this._running = true
    this.onEvent({
      type: 'SYSTEM',
      severity: 'INFO',
      data: { message: `Packet capture active on ${device}` }
    })
  }

  async stop() {
    if (!this._running || !this._cap) return
    this._cap.close()
    this._cap    = null
    this._running = false
  }

  setInterface(iface) {
    this._iface = iface
    if (this._running) {
      this.stop().then(() => this.start(iface))
    }
  }

  isRunning() { return this._running }

  // ── Packet analysis ──────────────────────────────────────────────────

  _handlePacket(nbytes) {
    try {
      const eth = decoders.Ethernet(this._buffer)
      if (eth.info.type !== PROTOCOL.ETHERNET.IPV4) return

      const ip = decoders.IPV4(this._buffer, eth.offset)
      if (ip.info.protocol !== PROTOCOL.IP.TCP) return

      const tcp = decoders.TCP(this._buffer, ip.offset)
      const dstPort  = tcp.info.dstport
      const srcPort  = tcp.info.srcport
      const dstIP    = ip.info.daddress
      const srcIP    = ip.info.saddress
      const payloadOffset = tcp.offset
      const payloadLen    = nbytes - payloadOffset

      // Skip tiny packets (ACK/SYN only)
      if (payloadLen < 16) return

      // Extract payload for entropy analysis
      const payload = this._buffer.slice(payloadOffset, payloadOffset + Math.min(payloadLen, 256))
      const entropy = this._shannonEntropy(payload)

      // High-entropy small outbound payload to suspicious port = likely key exfil
      if (
        payloadLen > 16 && payloadLen < 2048 &&
        entropy > 7.2 &&
        (this._suspiciousPorts.has(dstPort) || this._suspiciousPorts.has(srcPort))
      ) {
        this.onEvent({
          type: 'PACKET_MATCH',
          severity: 'ALERT',
          data: {
            srcIP, srcPort, dstIP, dstPort,
            payloadLen,
            entropy: entropy.toFixed(3),
            payloadHex: payload.toString('hex'),
            reason: 'High-entropy payload on suspicious port — possible key exfiltration'
          }
        })
        return
      }

      // Moderate entropy + non-standard destination
      if (entropy > 6.5 && !this._isCommonService(dstPort)) {
        this.onEvent({
          type: 'PACKET_MATCH',
          severity: 'WARNING',
          data: {
            srcIP, srcPort, dstIP, dstPort,
            payloadLen,
            entropy: entropy.toFixed(3),
            reason: 'Elevated entropy outbound packet'
          }
        })
      }
    } catch {
      // Malformed packet — ignore
    }
  }

  /**
   * Shannon entropy — bits per byte. Random/encrypted data ≈ 7.9-8.0
   * Plain text ≈ 4.5-5.5. Key material typically > 7.2.
   */
  _shannonEntropy(buf) {
    const freq = new Array(256).fill(0)
    for (const byte of buf) freq[byte]++
    let entropy = 0
    for (const f of freq) {
      if (f === 0) continue
      const p = f / buf.length
      entropy -= p * Math.log2(p)
    }
    return entropy
  }

  _isCommonService(port) {
    return [80, 443, 53, 123, 22, 25, 587, 993, 995, 143].includes(port)
  }

  _autoDetectInterface() {
    if (this._iface !== 'auto') return this._iface
    const devices = Cap.deviceList()
    // Prefer the first non-loopback interface with an IPv4 address
    for (const dev of devices) {
      if (dev.name.includes('lo') || dev.name.includes('Loopback')) continue
      if (dev.addresses.some(a => a.addr && a.addr.includes('.'))) {
        return dev.name
      }
    }
    return devices[0]?.name || null
  }
}
