import { useEffect, useRef } from 'react'

// Generates a single column of falling matrix characters
function MatrixColumn({ left, duration, delay, chars }) {
  return (
    <div
      className="matrix-col"
      style={{ left, animationDuration: `${duration}s`, animationDelay: `${delay}s` }}
    >
      {chars}
    </div>
  )
}

// Ambient matrix rain — 8 columns across the sidebar only
function MatrixRain() {
  const CHARS = '01アイウエオカキクケコサシスセソ'
  const cols = Array.from({ length: 8 }, (_, i) => ({
    left:     `${i * 28}px`,
    duration: 6 + Math.random() * 8,
    delay:    -(Math.random() * 10),
    chars:    Array.from({ length: 30 }, () =>
      CHARS[Math.floor(Math.random() * CHARS.length)]
    ).join('\n')
  }))
  return (
    <div style={{
      position: 'absolute', inset: 0, overflow: 'hidden',
      pointerEvents: 'none', opacity: 0.6
    }}>
      {cols.map((c, i) => <MatrixColumn key={i} {...c} />)}
    </div>
  )
}

export default function Sidebar({ page, onNavigate, status, alerts }) {
  const running   = status?.running ?? false
  const alertBadge = alerts.length

  const navItems = [
    { id: 'dashboard', icon: '◈', label: 'Dashboard' },
    { id: 'events',    icon: '⟁', label: 'Event Feed',
      badge: alertBadge || null },
    { id: 'log',       icon: '⊟', label: 'Secure Log' },
    { id: 'settings',  icon: '⚙', label: 'Settings' },
  ]

  return (
    <div className="sidebar" style={{ position: 'relative', overflow: 'hidden' }}>
      {/* Ambient matrix rain behind everything */}
      <MatrixRain />

      {/* Content sits above the rain */}
      <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', height: '100%' }}>

        {/* macOS drag region */}
        <div className="titlebar-drag" />

        {/* Logo block */}
        <div style={{
          padding: '0 16px 16px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 8
        }}>
          {/* Logo image — references bundled resource */}
          <div style={{
            width: 80,
            height: 80,
            borderRadius: 8,
            overflow: 'hidden',
            border: '1px solid rgba(51,255,51,0.25)',
            boxShadow: '0 0 16px rgba(51,255,51,0.2), 0 0 40px rgba(51,255,51,0.08)',
            flexShrink: 0
          }}>
            <img
              src="../../resources/icons/icon.png"
              alt="Chaveiros"
              style={{ width: '100%', height: '100%', objectFit: 'cover' }}
              onError={e => { e.target.style.display = 'none' }}
            />
          </div>

          {/* CHAVEIROS metallic title */}
          <div style={{ textAlign: 'center' }}>
            <div className="metallic" style={{ fontSize: 15, letterSpacing: '0.15em' }}>
              CHAVEIROS
            </div>
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--neon)',
              opacity: 0.6,
              letterSpacing: '0.12em',
              marginTop: 2
            }}>
              RANSOMWARE DEFENSE
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav" style={{ flex: 1 }}>
          {navItems.map(item => (
            <button
              key={item.id}
              className={`nav-item ${page === item.id ? 'active' : ''}`}
              onClick={() => onNavigate(item.id)}
              style={page === item.id ? {
                background: 'rgba(51,255,51,0.08)',
                color: 'var(--neon)',
                borderColor: 'rgba(51,255,51,0.25)',
                textShadow: '0 0 8px rgba(51,255,51,0.5)'
              } : {}}
            >
              <span className="nav-icon" style={page === item.id ? { color: 'var(--neon)' } : {}}>
                {item.icon}
              </span>
              <span style={{ flex: 1 }}>{item.label}</span>
              {item.badge ? (
                <span style={{
                  background: 'var(--fire)',
                  color: '#fff',
                  borderRadius: 10,
                  padding: '1px 6px',
                  fontSize: 10,
                  fontWeight: 700,
                  boxShadow: '0 0 6px rgba(255,107,26,0.5)'
                }}>
                  {item.badge > 99 ? '99+' : item.badge}
                </span>
              ) : null}
            </button>
          ))}
        </nav>

        {/* Scanner status */}
        <div className="sidebar-status" style={{ position: 'relative' }}>
          <div className="card-label" style={{ color: 'var(--text-3)' }}>Scanner Status</div>

          <span className={`pill ${running ? 'pill-green' : 'pill-red'}`} style={{
            ...(running ? { boxShadow: '0 0 8px rgba(51,255,51,0.3)' } : {})
          }}>
            <span className={`dot ${running ? 'dot-pulse' : ''}`} />
            {running ? 'ACTIVE' : 'STOPPED'}
          </span>

          {status && (
            <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 5 }}>
              {Object.entries(status.scanners || {}).map(([name, active]) => (
                <div key={name} style={{
                  display: 'flex', alignItems: 'center',
                  justifyContent: 'space-between',
                  fontSize: 10.5,
                }}>
                  <span style={{ color: 'var(--text-3)', textTransform: 'capitalize' }}>
                    {name}
                  </span>
                  <span style={{
                    color: active ? 'var(--neon)' : 'var(--text-3)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    ...(active ? { textShadow: '0 0 6px var(--neon)' } : {})
                  }}>
                    {active ? '● ON' : '○ OFF'}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Binary decoration — matches logo */}
          <div style={{
            marginTop: 12,
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: 'rgba(51,255,51,0.2)',
            letterSpacing: '0.08em',
            textAlign: 'center'
          }}>
            01010011 · 11010011
          </div>
        </div>
      </div>
    </div>
  )
}
