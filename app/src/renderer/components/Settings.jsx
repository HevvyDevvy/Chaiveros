import { useState, useEffect } from 'react'

export default function Settings({ privileges, logPath }) {
  const [cfg,       setCfg]       = useState(null)
  const [saved,     setSaved]     = useState(false)
  const [ppCurrent, setPpCurrent] = useState('')
  const [ppNew,     setPpNew]     = useState('')
  const [ppConfirm, setPpConfirm] = useState('')
  const [ppMsg,     setPpMsg]     = useState('')
  const [interfaces, setInterfaces] = useState([])

  useEffect(() => {
    window.rwd.settings.get().then(setCfg)
  }, [])

  if (!cfg) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--neon)', fontFamily: 'var(--font-mono)' }}>
      ⟳ Loading settings…
    </div>
  )

  const set = (key, value) => {
    setCfg(c => ({ ...c, [key]: value }))
    window.rwd.settings.set(key, value)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const browseLog = async () => {
    const p = await window.rwd.dialog.saveFile({
      defaultPath: cfg.logPath,
      filters: [{ name: 'RWD Log', extensions: ['rwdlog'] }]
    })
    if (p) { set('logPath', p); window.rwd.log.setPath(p) }
  }

  const changePassphrase = () => {
    if (ppNew.length < 8) { setPpMsg('New passphrase must be at least 8 characters'); return }
    if (ppNew !== ppConfirm) { setPpMsg('New passphrases do not match'); return }
    window.rwd.log.setPassphrase(ppNew)
    setPpMsg('Passphrase updated — new key applied to all future log entries')
    setPpCurrent(''); setPpNew(''); setPpConfirm('')
    setTimeout(() => setPpMsg(''), 4000)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="page-title metallic">Settings</span>
          {saved && (
            <span className="pill pill-green" style={{ fontSize: 10 }}>
              ✓ Saved
            </span>
          )}
        </div>
      </div>

      <div className="page-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* ── Privilege status ─────────────────────────────────────── */}
        {privileges && (
          <Section title="System Privileges" icon="⚙">
            <PrivilegeGrid privileges={privileges} />
          </Section>
        )}

        {/* ── Scanner controls ─────────────────────────────────────── */}
        <Section title="Scanner Modules" icon="◈">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <Toggle
              label="Library hooks (Frida)"
              sub="Intercepts encryption library calls in running processes"
              value={cfg.monitorLibraries}
              onChange={v => set('monitorLibraries', v)}
            />
            <Toggle
              label="Packet capture"
              sub={`Monitors network traffic for key exfiltration${!privileges?.canSniff ? ' — needs root/admin + libpcap' : ''}`}
              value={cfg.monitorPackets}
              onChange={v => set('monitorPackets', v)}
              disabled={!privileges?.canSniff}
            />
            <Toggle
              label="Process monitor"
              sub="Watches for anomalous CPU spikes and file descriptor explosion"
              value={cfg.monitorMemory}
              onChange={v => set('monitorMemory', v)}
            />
            <Toggle
              label="Kernel scanner"
              sub={`Loads compiled kernel module for lowest-level key detection${!privileges?.canLoadKernel ? ' — needs root/admin' : ''}`}
              value={cfg.monitorKernel}
              onChange={v => set('monitorKernel', v)}
              disabled={!privileges?.canLoadKernel}
            />
          </div>
        </Section>

        {/* ── Alert threshold ───────────────────────────────────────── */}
        <Section title="Alert Threshold" icon="⟁">
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <input
              type="range" min={1} max={50}
              value={cfg.alertThreshold}
              onChange={e => set('alertThreshold', Number(e.target.value))}
              style={{ flex: 1, accentColor: 'var(--neon)' }}
            />
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 18,
              color: 'var(--neon)',
              minWidth: 32,
              textAlign: 'right',
              textShadow: '0 0 8px var(--neon)'
            }}>
              {cfg.alertThreshold}
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>
            Fire an alert after this many key interception events
          </div>
        </Section>

        {/* ── Network interface ─────────────────────────────────────── */}
        <Section title="Network Interface" icon="⊟">
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              className="input input-mono"
              value={cfg.networkInterface}
              onChange={e => set('networkInterface', e.target.value)}
              placeholder="auto"
              style={{ flex: 1 }}
            />
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 6 }}>
            Interface for packet capture: eth0 / en0 / Ethernet / auto
          </div>
        </Section>

        {/* ── Secure log ───────────────────────────────────────────── */}
        <Section title="Secure Log" icon="⊟">
          <div style={{ marginBottom: 10 }}>
            <Label>Log file path</Label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                className="input input-mono"
                value={cfg.logPath}
                onChange={e => set('logPath', e.target.value)}
                style={{ flex: 1 }}
                readOnly
              />
              <button className="btn btn-ghost" onClick={browseLog}>Browse</button>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>
              AES-256-GCM encrypted · hash-chained · append-only
            </div>
          </div>

          {/* Passphrase change */}
          <div style={{
            marginTop: 12,
            padding: 14,
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            borderRadius: 6
          }}>
            <Label>Change passphrase</Label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7, marginTop: 6 }}>
              <input
                className="input"
                type="password"
                placeholder="Current passphrase"
                value={ppCurrent}
                onChange={e => setPpCurrent(e.target.value)}
              />
              <input
                className="input"
                type="password"
                placeholder="New passphrase (min 8 chars)"
                value={ppNew}
                onChange={e => setPpNew(e.target.value)}
              />
              <input
                className="input"
                type="password"
                placeholder="Confirm new passphrase"
                value={ppConfirm}
                onChange={e => setPpConfirm(e.target.value)}
              />
              {ppMsg && (
                <div style={{
                  fontSize: 11,
                  color: ppMsg.includes('updated') ? 'var(--neon)' : 'var(--fire)',
                  padding: '5px 8px',
                  background: ppMsg.includes('updated') ? 'var(--neon-glow)' : 'var(--fire-dim)',
                  borderRadius: 4
                }}>
                  {ppMsg}
                </div>
              )}
              <button className="btn btn-ghost" onClick={changePassphrase}>
                Update passphrase
              </button>
            </div>
          </div>

          <div style={{
            marginTop: 10,
            fontFamily: 'var(--font-mono)',
            fontSize: 10,
            color: 'var(--text-3)',
            padding: '8px 10px',
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 4
          }}>
            Cipher: AES-256-GCM · KDF: PBKDF2-SHA256 (210,000 iter) · Chain: SHA-256
          </div>
        </Section>

        {/* ── About ─────────────────────────────────────────────────── */}
        <Section title="About" icon="◈">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, color: 'var(--text-2)' }}>
            <Row label="Tool"      value="Chaveiros — Ransomware Defense" />
            <Row label="Author"    value="Blu Corbel · @TheMadHattersPlayground.com" />
            <Row label="GitHub"    value="DeadmanXXXII/Ransomeware_Defense" />
            <Row label="License"   value="MIT with Authorized Use clause" />
            <Row label="Engine"    value="Electron + Frida + cap (libpcap)" />
          </div>
          <div style={{
            marginTop: 12,
            fontSize: 10,
            color: 'var(--text-3)',
            padding: '8px 10px',
            background: 'var(--surface)',
            border: '1px solid rgba(255,107,26,0.2)',
            borderRadius: 4,
            lineHeight: 1.7
          }}>
            ⚠ Authorized use only — deploy only on systems you own or have explicit written permission to monitor.
          </div>
        </Section>

      </div>
    </div>
  )
}

// ── Small helpers ─────────────────────────────────────────────────────────

function Section({ title, icon, children }) {
  return (
    <div className="card">
      <div style={{
        display: 'flex', alignItems: 'center', gap: 7,
        marginBottom: 12
      }}>
        <span style={{ color: 'var(--neon)', fontSize: 13 }}>{icon}</span>
        <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--silver-2, var(--text-2))' }}>
          {title}
        </span>
      </div>
      {children}
    </div>
  )
}

function Label({ children }) {
  return (
    <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: 5 }}>
      {children}
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div style={{ display: 'flex', gap: 12 }}>
      <span style={{ color: 'var(--text-3)', width: 80, flexShrink: 0 }}>{label}</span>
      <span style={{ color: 'var(--text-2)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{value}</span>
    </div>
  )
}

function Toggle({ label, sub, value, onChange, disabled }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 12,
      opacity: disabled ? 0.4 : 1
    }}>
      <div
        onClick={() => !disabled && onChange(!value)}
        style={{
          width: 36, height: 20, borderRadius: 10,
          background: value ? 'var(--neon)' : 'var(--surface-3)',
          border: `1px solid ${value ? 'var(--neon)' : 'var(--border)'}`,
          position: 'relative',
          cursor: disabled ? 'not-allowed' : 'pointer',
          transition: 'background 0.2s, box-shadow 0.2s',
          boxShadow: value ? '0 0 8px rgba(51,255,51,0.4)' : 'none',
          flexShrink: 0
        }}
      >
        <div style={{
          position: 'absolute',
          top: 2, left: value ? 17 : 2,
          width: 14, height: 14,
          borderRadius: '50%',
          background: value ? '#060906' : 'var(--text-3)',
          transition: 'left 0.2s'
        }} />
      </div>
      <div>
        <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text)' }}>{label}</div>
        {sub && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1 }}>{sub}</div>}
      </div>
    </div>
  )
}

function PrivilegeGrid({ privileges }) {
  const items = [
    { label: 'Elevated (root/admin)', ok: privileges.isElevated },
    { label: 'Packet capture',        ok: privileges.canSniff },
    { label: 'Memory read',           ok: privileges.canReadMemory },
    { label: 'Kernel module',         ok: privileges.canLoadKernel },
  ]
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
      {items.map(({ label, ok }) => (
        <div key={label} style={{
          display: 'flex', alignItems: 'center', gap: 8,
          fontSize: 12
        }}>
          <span style={{
            color: ok ? 'var(--neon)' : 'var(--fire)',
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            textShadow: ok ? '0 0 6px var(--neon)' : 'none'
          }}>
            {ok ? '●' : '○'}
          </span>
          <span style={{ color: ok ? 'var(--text-2)' : 'var(--text-3)' }}>{label}</span>
        </div>
      ))}
      {privileges.details?.hint && (
        <div style={{
          gridColumn: '1/-1', fontSize: 11,
          color: 'var(--amber)', marginTop: 4
        }}>
          ⚠ {privileges.details.hint}
        </div>
      )}
    </div>
  )
}
