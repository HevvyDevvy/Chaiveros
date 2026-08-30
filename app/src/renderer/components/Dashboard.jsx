import { useState } from 'react'

export default function Dashboard({
  events, alerts, status, privileges, startScanner, stopScanner
}) {
  const [starting, setStarting] = useState(false)
  const running = status?.running ?? false

  const handleStart = async () => {
    setStarting(true)
    await startScanner()
    setTimeout(() => setStarting(false), 1500)
  }

  const keyEvents    = events.filter(e => e.type === 'KEY_INTERCEPTED' || e.type === 'KERNEL_KEY_EVENT')
  const packetEvents = events.filter(e => e.type === 'PACKET_MATCH')
  const alertEvents  = events.filter(e => e.severity === 'ALERT')
  const warnEvents   = events.filter(e => e.severity === 'WARNING')

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* Header */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span className="page-title metallic" style={{ fontSize: 15 }}>Dashboard</span>
          {running && (
            <span className="pill pill-green" style={{ fontSize: 10 }}>
              <span className="dot dot-pulse" /> SCANNING
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {running
            ? (
              <button
                className="btn btn-danger"
                onClick={stopScanner}
                style={{ boxShadow: '0 0 10px rgba(255,51,51,0.25)' }}
              >
                ■ Stop
              </button>
            ) : (
              <button
                className="btn btn-primary"
                onClick={handleStart}
                disabled={starting}
                style={{ padding: '8px 20px', fontSize: 13 }}
              >
                {starting ? '⟳ Starting…' : '▶ Start Scanning'}
              </button>
            )
          }
        </div>
      </div>

      <div className="page-body">

        {/* Privilege warnings */}
        {privileges && <PrivilegeWarnings privileges={privileges} />}

        {/* Threshold breach alert banner */}
        {alerts.length > 0 && (
          <div className="fire-alert fade-in" style={{
            borderRadius: 8,
            padding: '12px 16px',
            marginBottom: 16,
            display: 'flex',
            alignItems: 'center',
            gap: 12
          }}>
            <span style={{ fontSize: 22 }}>🔥</span>
            <div>
              <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--fire)' }}>
                Alert threshold breached
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 2 }}>
                {alerts[0].data?.message}
              </div>
            </div>
          </div>
        )}

        {/* Stat cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 12,
          marginBottom: 20
        }}>
          <StatCard
            label="Keys Intercepted"
            value={keyEvents.length}
            color="var(--neon)"
            glow="rgba(51,255,51,0.3)"
            icon="🗝"
          />
          <StatCard
            label="Packet Matches"
            value={packetEvents.length}
            color="var(--amber)"
            glow="rgba(255,179,71,0.2)"
            icon="⟁"
          />
          <StatCard
            label="Active Alerts"
            value={alertEvents.length}
            color="var(--fire)"
            glow="rgba(255,107,26,0.25)"
            icon="🔥"
          />
          <StatCard
            label="Total Events"
            value={events.length}
            color="var(--silver)"
            glow="rgba(200,212,200,0.15)"
            icon="◈"
          />
        </div>

        {/* Sub-system status + threshold */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>

          <div className="card" style={running ? { borderColor: 'rgba(51,255,51,0.2)', boxShadow: '0 0 12px rgba(51,255,51,0.06)' } : {}}>
            <div className="card-label">Sub-systems</div>
            {status ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 6 }}>
                {Object.entries(status.scanners || {}).map(([name, active]) => (
                  <SubsystemRow key={name} name={name} active={active} />
                ))}
              </div>
            ) : (
              <div style={{
                fontSize: 12, color: 'var(--text-3)',
                fontFamily: 'var(--font-mono)', marginTop: 6
              }}>
                — Start scanning to initialise sub-systems
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-label">Threshold Progress</div>
            <div style={{ marginTop: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 32,
                  fontWeight: 300,
                  color: 'var(--neon)',
                  textShadow: '0 0 16px rgba(51,255,51,0.5)',
                  lineHeight: 1
                }}>
                  {status?.alertCount ?? 0}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-3)' }}>
                  / {status?.threshold ?? 5} events
                </span>
              </div>

              {/* Segmented threshold bar */}
              <div style={{ display: 'flex', gap: 3 }}>
                {Array.from({ length: status?.threshold ?? 5 }).map((_, i) => {
                  const filled = i < (status?.alertCount ?? 0)
                  return (
                    <div key={i} style={{
                      flex: 1, height: 6, borderRadius: 3,
                      background: filled ? 'var(--neon)' : 'var(--surface-2)',
                      boxShadow: filled ? '0 0 6px rgba(51,255,51,0.5)' : 'none',
                      transition: 'background 0.3s, box-shadow 0.3s'
                    }} />
                  )
                })}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 5 }}>
                Key events since last alert dispatch
              </div>
            </div>
          </div>
        </div>

        {/* Recent key intercepts — the main event */}
        {keyEvents.length > 0 && (
          <div className="card" style={{
            borderColor: 'rgba(51,255,51,0.2)',
            marginBottom: 16
          }}>
            <div className="card-label" style={{ color: 'var(--neon)' }}>
              Recent Key Intercepts
            </div>
            <div style={{ marginTop: 4 }}>
              {keyEvents.slice(0, 3).map((ev, i) => (
                <KeyInterceptRow key={i} event={ev} />
              ))}
            </div>
          </div>
        )}

        {/* Recent alerts list */}
        {alerts.slice(0, 3).map((alert, i) => (
          <div key={i} className="card fire-alert fade-in" style={{ marginBottom: 10 }}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'start' }}>
              <span style={{ fontSize: 16, flexShrink: 0 }}>⚠</span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--fire)' }}>
                  {alert.type?.replace(/_/g, ' ')}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 2 }}>
                  {alert.data?.message}
                </div>
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10,
                  color: 'var(--text-3)',
                  marginTop: 3
                }}>
                  {new Date(alert.ts).toLocaleTimeString('en-GB', { hour12: false })}
                </div>
              </div>
            </div>
          </div>
        ))}

        {/* Empty state */}
        {!running && events.length === 0 && (
          <div style={{
            display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center',
            padding: '80px 0', color: 'var(--text-3)', gap: 14
          }}>
            <div style={{
              fontSize: 56, opacity: 0.15,
              filter: 'drop-shadow(0 0 20px rgba(51,255,51,0.3))'
            }}>
              🛡
            </div>
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 13,
              color: 'var(--text-3)',
              letterSpacing: '0.1em'
            }}>
              SCANNER OFFLINE
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
              Press Start Scanning to begin monitoring this system
            </div>
            {/* Binary decoration */}
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: 'rgba(51,255,51,0.12)',
              letterSpacing: '0.15em',
              marginTop: 8
            }}>
              01010011 · 11010011
            </div>
          </div>
        )}

      </div>
    </div>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────

function StatCard({ label, value, color, glow, icon }) {
  return (
    <div className="card" style={{
      textAlign: 'center',
      position: 'relative',
      overflow: 'hidden',
      transition: 'box-shadow 0.3s',
      ...(value > 0 ? { boxShadow: `0 0 16px ${glow}`, borderColor: `${color}33` } : {})
    }}>
      <div style={{ fontSize: 20, marginBottom: 6 }}>{icon}</div>
      <div style={{
        fontSize: 32,
        fontWeight: 300,
        fontFamily: 'var(--font-mono)',
        color,
        lineHeight: 1,
        textShadow: value > 0 ? `0 0 16px ${glow}` : 'none',
        transition: 'text-shadow 0.3s'
      }}>
        {value}
      </div>
      <div className="card-label" style={{ marginTop: 8, marginBottom: 0 }}>{label}</div>
    </div>
  )
}

function SubsystemRow({ name, active }) {
  const meta = {
    frida:   { icon: '⟁', label: 'Library hooks (Frida)' },
    packet:  { icon: '⊟', label: 'Packet capture' },
    process: { icon: '◈', label: 'Process monitor' },
    kernel:  { icon: '⚙', label: 'Kernel scanner' }
  }
  const { icon, label } = meta[name] || { icon: '○', label: name }
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
      <span style={{ color: active ? 'var(--neon)' : 'var(--text-3)', width: 16 }}>{icon}</span>
      <span style={{ flex: 1, color: 'var(--text-2)' }}>{label}</span>
      <span style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: active ? 'var(--neon)' : 'var(--text-3)',
        textShadow: active ? '0 0 6px var(--neon)' : 'none'
      }}>
        {active ? '● ON' : '○ OFF'}
      </span>
    </div>
  )
}

function KeyInterceptRow({ event }) {
  const d = event.data || {}
  return (
    <div style={{
      padding: '8px 0',
      borderBottom: '1px solid var(--border)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
        <span style={{ fontSize: 11, color: 'var(--text-2)' }}>
          {d.processName || 'unknown'} · PID {d.pid || '?'} · {d.algorithm || 'unknown'}
        </span>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          color: 'var(--text-3)'
        }}>
          {new Date(event.ts).toLocaleTimeString('en-GB', { hour12: false })}
        </span>
      </div>
      {d.keyHex && (
        <div className="key-data" style={{
          fontSize: 10,
          letterSpacing: '0.04em',
          boxShadow: '0 0 8px rgba(51,255,51,0.12)'
        }}>
          {d.keyHex.slice(0, 64)}{d.keyHex.length > 64 ? '…' : ''}
        </div>
      )}
    </div>
  )
}

function PrivilegeWarnings({ privileges }) {
  const warnings = []
  if (!privileges.isElevated)
    warnings.push('Not running as root/admin — packet capture, memory scan and kernel module unavailable')
  if (!privileges.canSniff && privileges.isElevated)
    warnings.push('Packet capture unavailable — install libpcap (Linux/macOS) or Npcap (Windows)')
  if (privileges.details?.sipEnabled)
    warnings.push('macOS SIP enabled — kernel extension cannot load. See docs/macos-compat.md')
  if (privileges.details?.npcap === false)
    warnings.push('Npcap not installed — download from npcap.com for Windows packet capture')

  if (!warnings.length) return null

  return (
    <div style={{ marginBottom: 16, display: 'flex', flexDirection: 'column', gap: 6 }}>
      {warnings.map((w, i) => (
        <div key={i} style={{
          background: 'rgba(255,179,71,0.06)',
          border: '1px solid rgba(255,179,71,0.2)',
          borderRadius: 6, padding: '8px 12px',
          fontSize: 12, color: 'var(--amber)',
          display: 'flex', gap: 8, alignItems: 'start'
        }}>
          <span style={{ flexShrink: 0 }}>⚠</span>
          <span>{w}</span>
        </div>
      ))}
    </div>
  )
}
