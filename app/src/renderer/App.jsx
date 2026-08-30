import { useState, useEffect, useCallback, useRef } from 'react'
import Sidebar    from './components/Sidebar.jsx'
import Dashboard  from './components/Dashboard.jsx'
import EventFeed  from './components/EventFeed.jsx'
import LogViewer  from './components/LogViewer.jsx'
import Settings   from './components/Settings.jsx'

const MAX_EVENTS = 500

export default function App() {
  const [page,       setPage]      = useState('dashboard')
  const [events,     setEvents]    = useState([])
  const [alerts,     setAlerts]    = useState([])
  const [status,     setStatus]    = useState(null)
  const [privileges, setPrivileges]= useState(null)
  const [logPath,    setLogPath]   = useState('')

  // ── Subscribe to scanner events from main process ───────────────────
  useEffect(() => {
    const unsubEvent = window.rwd.on('scanner:event', (event) => {
      setEvents(prev => {
        const next = [{ ...event, _id: crypto.randomUUID() }, ...prev]
        return next.slice(0, MAX_EVENTS)
      })
    })

    const unsubAlert = window.rwd.on('scanner:alert', (alert) => {
      setAlerts(prev => [{ ...alert, _id: crypto.randomUUID() }, ...prev].slice(0, 50))
    })

    const unsubPrivs = window.rwd.on('app:privileges', (privs) => {
      setPrivileges(privs)
    })

    const unsubLog = window.rwd.on('app:logPath', (path) => {
      setLogPath(path)
    })

    // Poll status every 5 seconds
    const pollStatus = async () => {
      const s = await window.rwd.scanner.status()
      setStatus(s)
    }
    pollStatus()
    const statusInterval = setInterval(pollStatus, 5000)

    return () => {
      unsubEvent()
      unsubAlert()
      unsubPrivs()
      unsubLog()
      clearInterval(statusInterval)
    }
  }, [])

  const startScanner = useCallback(async () => {
    window.rwd.scanner.start()
    // Status will update via poll
    setTimeout(async () => {
      const s = await window.rwd.scanner.status()
      setStatus(s)
    }, 1000)
  }, [])

  const stopScanner = useCallback(async () => {
    window.rwd.scanner.stop()
    setTimeout(async () => {
      const s = await window.rwd.scanner.status()
      setStatus(s)
    }, 1000)
  }, [])

  const clearEvents = useCallback(() => setEvents([]), [])

  const pageProps = { events, alerts, status, privileges, logPath, startScanner, stopScanner, clearEvents }

  return (
    <div className="app-shell">
      {/* macOS traffic lights need drag region */}
      <Sidebar
        page={page}
        onNavigate={setPage}
        status={status}
        alerts={alerts}
      />

      <div className="main-content">
        {page === 'dashboard' && <Dashboard  {...pageProps} />}
        {page === 'events'    && <EventFeed  {...pageProps} />}
        {page === 'log'       && <LogViewer  {...pageProps} />}
        {page === 'settings'  && <Settings   {...pageProps} />}
      </div>
    </div>
  )
}
