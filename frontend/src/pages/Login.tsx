import { FormEvent, useEffect, useState } from 'react'
import { api, ApiError } from '../lib/api'

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [configured, setConfigured] = useState(true)

  useEffect(() => {
    api.authStatus()
      .then((s) => setConfigured(s.configured))
      .catch(() => setConfigured(true))
  }, [])

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      await api.login(password)
      onSuccess()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not sign in')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: '100vh', padding: 20 }}>
      <form className="card" onSubmit={submit}
            style={{ width: 'min(390px, 100%)', padding: 26 }}>
        <div className="brand" style={{ padding: '0 0 16px' }}>
          <span className="brand-mark">💾</span>
          <span>SMB Share Manager</span>
        </div>

        {!configured && (
          <div className="notice danger">
            <strong>ADMIN_PASSWORD is not set.</strong> Set it in
            <span className="mono"> .env</span> and restart the container.
          </div>
        )}

        <div className="field">
          <label htmlFor="pw">Admin password</label>
          <input id="pw" className="input" type="password" autoFocus
                 autoComplete="current-password"
                 value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>

        {error && <div className="notice danger">{error}</div>}

        <button className="btn primary" type="submit" disabled={busy || !password}
                style={{ width: '100%' }}>
          {busy ? <span className="spin" /> : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
