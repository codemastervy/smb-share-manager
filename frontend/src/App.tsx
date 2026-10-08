import { useCallback, useEffect, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { api, Info } from './lib/api'
import { ToastHost } from './components/Toast'
import { Files } from './pages/Files'
import { Import } from './pages/Import'
import { Shares } from './pages/Shares'
import { Users } from './pages/Users'
import { Login } from './pages/Login'

type AuthState = 'checking' | 'in' | 'out'

const NAV = [
  { to: '/files', label: 'Files', icon: '🗂️', end: false },
  { to: '/shares', label: 'Shares', icon: '🔗', end: false },
  { to: '/users', label: 'Users', icon: '👥', end: false },
  { to: '/import', label: 'Import', icon: '📥', end: false },
]

export default function App() {
  const [auth, setAuth] = useState<AuthState>('checking')
  const [menuOpen, setMenuOpen] = useState(false)
  const [theme, setTheme] = useState(
    () => localStorage.getItem('ssm-theme') ?? 'dark')
  const [info, setInfo] = useState<Info | null>(null)
  const location = useLocation()

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('ssm-theme', theme)
  }, [theme])

  const check = useCallback(async () => {
    try {
      const status = await api.authStatus()
      setAuth(status.authenticated ? 'in' : 'out')
    } catch {
      // A 503 here means the server is up but misconfigured (no password set).
      // Showing the login screen is the honest outcome -- it carries the
      // server's own error text.
      setAuth('out')
    }
  }, [])

  useEffect(() => { void check() }, [check])

  // Any API call that 401s pushes us back to the login screen, so an expired
  // session does not leave a half-broken page on screen.
  useEffect(() => {
    const onUnauth = () => setAuth('out')
    window.addEventListener('ssm:unauthenticated', onUnauth)
    return () => window.removeEventListener('ssm:unauthenticated', onUnauth)
  }, [])

  useEffect(() => { setMenuOpen(false) }, [location.pathname])

  useEffect(() => {
    if (auth !== 'in') return
    api.info().then(setInfo).catch(() => {})
  }, [auth, location.pathname])

  if (auth === 'checking') {
    return <div style={{ display: 'grid', placeItems: 'center', height: '100vh' }}>
      <span className="spin" />
    </div>
  }

  if (auth === 'out') return <Login onSuccess={() => setAuth('in')} />

  return (
    <ToastHost>
      <div className="shell">
        {menuOpen && <div className="scrim" onClick={() => setMenuOpen(false)} />}

        <aside className={`sidebar ${menuOpen ? 'open' : ''}`}>
          <div className="brand">
            <span className="brand-mark">💾</span>
            <span>SMB Share Manager</span>
          </div>

          <nav className="stack" style={{ gap: 2 }}>
            {NAV.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end}
                       className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
                <span className="nav-icon">{item.icon}</span>{item.label}
              </NavLink>
            ))}
          </nav>

          <div className="sidebar-foot">
            {info && (
              <div className="host-chip">
                <strong>{info.server_name}</strong>
                {info.version} · built {info.build_date.slice(0, 10)}
              </div>
            )}
            <button className="nav-link"
                    onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
              <span className="nav-icon">{theme === 'dark' ? '☀️' : '🌙'}</span>
              {theme === 'dark' ? 'Light mode' : 'Dark mode'}
            </button>
            <button className="nav-link" onClick={async () => {
              await api.logout().catch(() => {})
              setAuth('out')
            }}>
              <span className="nav-icon">🚪</span>Sign out
            </button>
          </div>
        </aside>

        <div className="main">
          {info?.import_mounted && (
            <div className="notice warn import-banner">
              <strong>Import data is still mounted.</strong> It contains password hashes.
              When you have finished importing, remove the <span className="mono">./import</span> line
              from docker-compose.yml, delete <span className="mono">./import</span> on the server and
              run <span className="mono">docker compose up -d</span>.
            </div>
          )}
          <Routes>
            <Route path="/files/*" element={<Files onMenu={() => setMenuOpen(true)} />} />
            <Route path="/shares" element={<Shares onMenu={() => setMenuOpen(true)} />} />
            <Route path="/users" element={<Users onMenu={() => setMenuOpen(true)} />} />
            <Route path="/import" element={<Import onMenu={() => setMenuOpen(true)} />} />
            <Route path="*" element={<Navigate to="/files" replace />} />
          </Routes>
        </div>
      </div>
    </ToastHost>
  )
}

/** Shared page header with the mobile menu button. */
export function TopBar({ title, onMenu, children }: {
  title: string; onMenu: () => void; children?: React.ReactNode
}) {
  return (
    <header className="topbar">
      <button className="btn ghost icon menu-btn" onClick={onMenu} aria-label="Open menu">☰</button>
      <h1>{title}</h1>
      <div className="spacer" />
      {children}
    </header>
  )
}
