import { useState, useRef, useEffect } from 'react'

const TYPE_COLORS = {
  KEY_INTERCEPTED:  'var(--red)',
  KERNEL_KEY_EVENT: 'var(--red)',
  PACKET_MATCH:     'var(--amber)',
  PROCESS_MATCH:    'var(--red)',
  PROCESS_ANOMALY:  'var(--amber)',
  SYSTEM:           'var(--blue)',
}

const SEVERITY_CLASS = { ALERT: 'ALERT', WARNING: 'WARNING', INFO: 'INFO' }

export default function EventFeed({ events, clearEvents }) {
  const [filter,     setFilter]     = useState('')
  const [typeFilter, setTypeFilter] = useState('ALL')
  const [autoScroll, setAutoScroll] = useState(true)
  const feedRef = useRef(null)

  // Auto-scroll to top (newest events first)
  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = 0
    }
  }, [events, autoScroll])

  const filtered = events.filter(e => {
    if (typeFilter !== 'ALL' && e.type !== typeFilter) return false
    if (filter) {
      const s = JSON.stringify(e).toLowerCase()
      if (!s.includes(filter.toLowerCase())) return false
    }
    return true
  })

  const types = ['ALL', ...new Set(events.map(e => e.type))]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="page-header">
        <span className="page-title">Event Feed</span>
        <div style={{ display: 'flex', gap: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--text-3)', alignSelf: 'center' }}>
            {filtered.length} / {events.length}
          </span>
          <button className="btn btn-ghost" onClick={clearEvents}>Clear</button>
        </div>
      </div>

      {/* Filter bar */}
      <div style={{
        padding: '10px 24px',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        gap: 8,
        background: 'var(--surface)',
        flexShrink: 0
      }}>
        <input
          className="input"
          style={{ maxWidth: 280 }}
          placeholder="Filter events…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {types.slice(0, 6).map(t => (
            <button
              key={t}
              className={`btn ${typeFilter === t ? 'btn-primary' : 'btn-ghost'}`}
              style={{ padding: '4px 10px', fontSize: 11 }}
              onClick={() => setTypeFilter(t)}
            >
              {t === 'ALL' ? 'All' : t.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
        <label style={{
          display: 'flex', alignItems: 'center', gap: 6,
          fontSize: 11, color: 'var(--text-2)', marginLeft: 'auto', cursor: 'pointer'
        }}>
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={e => setAutoScroll(e.target.checked)}
          />
          Auto-scroll
        </label>
      </div>

      {/* Feed */}
      <div ref={feedRef} style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 ? (
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', height: '100%', color: 'var(--text-3)', gap: 10
          }}>
            <div style={{ fontSize: 28 }}>⟁</div>
            <div>No events yet — start the scanner to begin monitoring</div>
          </div>
        ) : (
          filtered.map(event => (
            <EventRow key={event._id} event={event} />
          ))
        )}
      </div>
    </div>
  )
}

function EventRow({ event }) {
  const [expanded, setExpanded] = useState(
    // Auto-expand key interception events
    event.type === 'KEY_INTERCEPTED' || event.type === 'KERNEL_KEY_EVENT'
  )
  const color = TYPE_COLORS[event.type] || 'var(--text-3)'
  const sevClass = SEVERITY_CLASS[event.severity] || 'INFO'
  const ts = new Date(event.ts).toLocaleTimeString('en-GB', { hour12: false })

  return (
    <div
      className={`event-item ${sevClass} fade-in`}
      style={{ cursor: 'pointer', gridTemplateColumns: '130px 140px 1fr' }}
      onClick={() => setExpanded(e => !e)}
    >
      <span className="event-ts">{ts}</span>

      <span className="event-type" style={{ color }}>
        {event.type?.replace(/_/g, ' ')}
      </span>

      <div>
        {/* Summary line */}
        <div className="event-body">
          {_summarise(event)}
        </div>

        {/* Expanded detail — the key reveal lives here */}
        {expanded && event.data?.keyHex && (
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>
              INTERCEPTED KEY — {event.data.algorithm || 'unknown'} ·
              PID {event.data.pid || '?'} · {event.data.processName || 'unknown process'}
            </div>
            {/* THE SIGNATURE MOMENT */}
            <div className="key-data key-scanline">
              <div className="key-reveal-wrap">
                <TypewriterKey value={event.data.keyHex} />
              </div>
            </div>
          </div>
        )}

        {/* Expanded detail — packet payload */}
        {expanded && event.type === 'PACKET_MATCH' && (
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>
              PACKET · {event.data?.srcIP}:{event.data?.srcPort} →
              {event.data?.dstIP}:{event.data?.dstPort} ·
              entropy {event.data?.entropy} · {event.data?.payloadLen}B
            </div>
            {event.data?.payloadHex && (
              <div className="key-data" style={{ color: 'var(--amber)' }}>
                {event.data.payloadHex.slice(0, 128)}
                {event.data.payloadHex.length > 128 ? '…' : ''}
              </div>
            )}
          </div>
        )}

        {/* Expanded detail — process info */}
        {expanded && (event.type === 'PROCESS_MATCH' || event.type === 'PROCESS_ANOMALY') && (
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-2)' }}>
            <span style={{ color: 'var(--text-3)' }}>PID</span> {event.data?.pid} ·
            <span style={{ color: 'var(--text-3)', marginLeft: 8 }}>Name</span> {event.data?.name} ·
            {event.data?.cpu && <><span style={{ color: 'var(--text-3)', marginLeft: 8 }}>CPU</span> {event.data.cpu}%</>}
          </div>
        )}
      </div>
    </div>
  )
}

/**
 * Typewriter reveal — the signature lime-mono animation for key data.
 * Characters appear at 18ms intervals giving the impression of decoding.
 */
function TypewriterKey({ value }) {
  const [shown, setShown] = useState(0)

  useEffect(() => {
    if (shown >= value.length) return
    // Group in pairs (hex bytes) for cleaner reveal
    const timer = setTimeout(() => setShown(s => Math.min(s + 2, value.length)), 18)
    return () => clearTimeout(timer)
  }, [shown, value])

  return (
    <span style={{ letterSpacing: '0.06em' }}>
      {value.slice(0, shown)}
      {shown < value.length && (
        <span style={{ opacity: 0.4, animation: 'pulse 0.5s ease infinite' }}>▌</span>
      )}
    </span>
  )
}

function _summarise(event) {
  const d = event.data || {}
  switch (event.type) {
    case 'KEY_INTERCEPTED':
    case 'KERNEL_KEY_EVENT':
      return `${d.algorithm || 'Key'} intercepted from ${d.processName || 'process'} (PID ${d.pid || '?'})`
    case 'PACKET_MATCH':
      return `${d.srcIP} → ${d.dstIP}:${d.dstPort} · entropy ${d.entropy} · ${d.reason}`
    case 'PROCESS_MATCH':
      return `${d.name} (PID ${d.pid}) — name matches signature "${d.signature}"`
    case 'PROCESS_ANOMALY':
      return `${d.name} (PID ${d.pid}) — ${d.reason}`
    case 'SYSTEM':
      return d.message || event.type
    default:
      return d.message || d.reason || event.type
  }
}
