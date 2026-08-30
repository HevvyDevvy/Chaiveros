import { useState, useEffect, useCallback } from 'react'

const TYPE_COLORS = {
  KEY_INTERCEPTED:    'var(--neon)',
  KERNEL_KEY_EVENT:   'var(--neon)',
  PACKET_MATCH:       'var(--amber)',
  PROCESS_MATCH:      'var(--fire)',
  PROCESS_ANOMALY:    'var(--amber)',
  THRESHOLD_BREACH:   'var(--fire)',
  SYSTEM:             'var(--text-2)',
}

export default function LogViewer({ logPath }) {
  const [unlocked,   setUnlocked]   = useState(false)
  const [passphrase, setPassphrase] = useState('')
  const [ppError,    setPpError]    = useState('')
  const [entries,    setEntries]    = useState([])
  const [total,      setTotal]      = useState(0)
  const [loading,    setLoading]    = useState(false)
  const [filter,     setFilter]     = useState('')
  const [chainBroken, setChainBroken] = useState(false)
  const [exporting,  setExporting]  = useState(false)

  // Check if already unlocked from a previous call this session
  useEffect(() => {
    window.rwd.log.isUnlocked().then(ok => {
      if (ok) { setUnlocked(true); loadEntries() }
    })
  }, [])

  const unlock = useCallback(async () => {
    if (passphrase.length < 8) {
      setPpError('Passphrase must be at least 8 characters')
      return
    }
    setPpError('')
    setLoading(true)
    window.rwd.log.setPassphrase(passphrase)
    // Give main process a moment to derive the key
    await new Promise(r => setTimeout(r, 600))
    const ok = await window.rwd.log.isUnlocked()
    if (ok) {
      setUnlocked(true)
      await loadEntries()
    } else {
      setPpError('Failed to unlock — check passphrase')
    }
    setLoading(false)
  }, [passphrase])

  const loadEntries = useCallback(async (f = '') => {
    setLoading(true)
    const result = await window.rwd.log.read({ limit: 300, filter: f || undefined })
    if (result.error) { setLoading(false); return }
    setEntries(result.entries || [])
    setTotal(result.total || 0)
    setChainBroken((result.entries || []).some(e => e._chainOK === false))
    setLoading(false)
  }, [])

  const handleExport = useCallback(async () => {
    const dest = await window.rwd.dialog.saveFile({
      defaultPath: `chaveiros-log-${Date.now()}.json`,
      filters: [{ name: 'JSON', extensions: ['json'] }]
    })
    if (!dest) return
    setExporting(true)
    const result = await window.rwd.log.export(dest)
    setExporting(false)
    alert(`Exported ${result.exported} entries to ${result.destPath}`)
  }, [])

  const handleClear = useCallback(() => {
    if (!confirm('Clear all log entries? This cannot be undone.')) return
    window.rwd.log.clear()
    setEntries([])
    setTotal(0)
  }, [])

  // ── Locked screen ──────────────────────────────────────────────────────
  if (!unlocked) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
        <div className="page-header">
          <span className="page-title metallic">Secure Log</span>
        </div>
        <div style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <div style={{
            width: 360,
            padding: 32,
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            textAlign: 'center'
          }}>
            {/* Padlock — matches logo padlock icons */}
            <div style={{
              fontSize: 48,
              marginBottom: 16,
              filter: 'drop-shadow(0 0 12px rgba(51,255,51,0.4))'
            }}>
              🔒
            </div>

            <div className="metallic" style={{ fontSize: 16, marginBottom: 6 }}>
              LOG LOCKED
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 24 }}>
              Enter your passphrase to decrypt the log
            </div>

            <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4, textAlign: 'left' }}>
              Log path
            </div>
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: 'var(--text-2)',
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '6px 8px',
              marginBottom: 16,
              wordBreak: 'break-all',
              textAlign: 'left'
            }}>
              {logPath || '—'}
            </div>

            <input
              className="input input-mono"
              type="password"
              placeholder="Passphrase (min 8 chars)"
              value={passphrase}
              onChange={e => setPassphrase(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && unlock()}
              style={{ marginBottom: 8 }}
              autoFocus
            />

            {ppError && (
              <div style={{
                fontSize: 11,
                color: 'var(--fire)',
                marginBottom: 12,
                padding: '6px 8px',
                background: 'var(--fire-dim)',
                borderRadius: 4,
                textAlign: 'left'
              }}>
                ⚠ {ppError}
              </div>
            )}

            <button
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: 4 }}
              onClick={unlock}
              disabled={loading}
            >
              {loading ? '⟳ Deriving key…' : '🔓 Unlock log'}
            </button>

            <div style={{ marginTop: 16, fontSize: 10, color: 'var(--text-3)' }}>
              PBKDF2-SHA256 · 210,000 iterations · AES-256-GCM
            </div>
          </div>
        </div>
      </div>
    )
  }

  // ── Unlocked screen ────────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="page-title metallic">Secure Log</span>
          <span className="pill pill-green" style={{ fontSize: 10 }}>
            <span className="dot" /> Decrypted
          </span>
          {chainBroken && (
            <span className="pill" style={{
              background: 'var(--fire-dim)',
              color: 'var(--fire)',
              fontSize: 10,
              border: '1px solid rgba(255,107,26,0.3)'
            }}>
              ⚠ Chain broken
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={handleExport} disabled={exporting}>
            {exporting ? '⟳ Exporting…' : '↓ Export JSON'}
          </button>
          <button className="btn btn-danger" onClick={handleClear}>Clear log</button>
        </div>
      </div>

      {/* Filter + stats bar */}
      <div style={{
        padding: '10px 24px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--surface)',
        display: 'flex',
        gap: 12,
        alignItems: 'center',
        flexShrink: 0
      }}>
        <input
          className="input"
          style={{ maxWidth: 260 }}
          placeholder="Search log entries…"
          value={filter}
          onChange={e => {
            setFilter(e.target.value)
            loadEntries(e.target.value)
          }}
        />
        <span style={{ fontSize: 11, color: 'var(--text-3)' }}>
          Showing {entries.length} of {total} entries
        </span>

        {chainBroken && (
          <div style={{
            marginLeft: 'auto',
            fontSize: 11,
            color: 'var(--fire)',
            background: 'var(--fire-dim)',
            border: '1px solid rgba(255,107,26,0.25)',
            borderRadius: 4,
            padding: '4px 10px'
          }}>
            ⚠ Hash chain violation detected — log may have been tampered with
          </div>
        )}
      </div>

      {/* Log entries */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {loading && (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: 120, color: 'var(--neon)', fontFamily: 'var(--font-mono)', fontSize: 12
          }}>
            ⟳ Decrypting entries…
          </div>
        )}

        {!loading && entries.length === 0 && (
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', height: 200, color: 'var(--text-3)', gap: 8
          }}>
            <div style={{ fontSize: 28 }}>⊟</div>
            <div>No log entries found</div>
            <div style={{ fontSize: 11 }}>Events are logged automatically when the scanner is running</div>
          </div>
        )}

        {!loading && entries.map((entry, idx) => (
          <LogEntry key={idx} entry={entry} />
        ))}
      </div>
    </div>
  )
}

function LogEntry({ entry }) {
  const [open, setOpen] = useState(entry.type === 'KEY_INTERCEPTED' || entry.type === 'KERNEL_KEY_EVENT')
  const color   = TYPE_COLORS[entry.type] || 'var(--text-2)'
  const ts      = new Date(entry.ts).toLocaleString('en-GB', { hour12: false })
  const tampered = entry._chainOK === false

  return (
    <div
      style={{
        borderBottom: '1px solid var(--border)',
        padding: '9px 24px',
        cursor: 'pointer',
        transition: 'background var(--duration)',
        ...(tampered ? {
          background: 'rgba(255,107,26,0.05)',
          borderLeft: '2px solid var(--fire)'
        } : {})
      }}
      onClick={() => setOpen(o => !o)}
      onMouseEnter={e => e.currentTarget.style.background = 'var(--surface-2)'}
      onMouseLeave={e => e.currentTarget.style.background = tampered ? 'rgba(255,107,26,0.05)' : ''}
    >
      {/* Row header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 10.5,
          color: 'var(--text-3)',
          flexShrink: 0,
          width: 170
        }}>
          {ts}
        </span>

        <span style={{
          fontSize: 10.5,
          fontWeight: 600,
          color,
          letterSpacing: '0.05em',
          width: 160,
          flexShrink: 0
        }}>
          {entry.type?.replace(/_/g, ' ')}
        </span>

        <span style={{
          fontSize: 12,
          color: 'var(--text-2)',
          flex: 1
        }}>
          {entry.data?.message || entry.data?.reason || _summarise(entry)}
        </span>

        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
          {tampered && (
            <span style={{
              fontSize: 10,
              color: 'var(--fire)',
              fontFamily: 'var(--font-mono)'
            }}>
              ⚠ TAMPERED
            </span>
          )}
          <SeverityPill s={entry.severity} />
          <span style={{ color: 'var(--text-3)', fontSize: 11 }}>{open ? '▲' : '▼'}</span>
        </div>
      </div>

      {/* Expanded — key data gets the full lime-mono signature treatment */}
      {open && (
        <div style={{ marginTop: 10, paddingLeft: 182 }}>
          {entry.data?.keyHex && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>
                INTERCEPTED KEY · {entry.data.algorithm} · PID {entry.data.pid}
              </div>
              <div className="key-data key-scanline">
                <div className="key-reveal-wrap">{entry.data.keyHex}</div>
              </div>
            </div>
          )}

          {/* Chain hash */}
          <div style={{
            marginTop: 6,
            fontFamily: 'var(--font-mono)',
            fontSize: 9.5,
            color: 'var(--text-3)',
            display: 'flex',
            gap: 8
          }}>
            <span style={{ color: tampered ? 'var(--fire)' : 'rgba(51,255,51,0.25)' }}>
              {tampered ? '✗ CHAIN BROKEN' : '✓ CHAIN OK'}
            </span>
            <span>prev: {(entry.prevHash || '').slice(0, 16)}…</span>
          </div>

          {/* Full data dump */}
          {entry.data && (
            <pre style={{
              marginTop: 8,
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: 'var(--text-2)',
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '8px 10px',
              overflowX: 'auto',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all'
            }}>
              {JSON.stringify(entry.data, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

function SeverityPill({ s }) {
  const map = {
    ALERT:   { cls: 'pill-red',   label: 'ALERT' },
    WARNING: { cls: 'pill-amber', label: 'WARN' },
    INFO:    { cls: 'pill-blue',  label: 'INFO' },
  }
  const { cls, label } = map[s] || map.INFO
  return <span className={`pill ${cls}`} style={{ fontSize: 9.5 }}>{label}</span>
}

function _summarise(entry) {
  const d = entry.data || {}
  switch (entry.type) {
    case 'KEY_INTERCEPTED':    return `${d.algorithm || 'Key'} from ${d.processName || 'unknown'}`
    case 'KERNEL_KEY_EVENT':   return d.raw || 'Kernel key event'
    case 'PACKET_MATCH':       return `${d.srcIP} → ${d.dstIP}:${d.dstPort} (entropy ${d.entropy})`
    case 'PROCESS_MATCH':      return `${d.name} (PID ${d.pid}) — signature "${d.signature}"`
    case 'PROCESS_ANOMALY':    return `${d.name} — ${d.reason}`
    case 'THRESHOLD_BREACH':   return d.message || 'Alert threshold breached'
    default:                   return JSON.stringify(d).slice(0, 80)
  }
}
