import { useCallback, useEffect, useState } from 'react'
import { TopBar } from '../App'
import { api, ImportScan, ImportedShare } from '../lib/api'
import { useToast } from '../components/Toast'

/** One-time import of users and shares from an old Samba server (e.g. CasaOS). */
export function Import({ onMenu }: { onMenu: () => void }) {
  const [scan, setScan] = useState<ImportScan | null>(null)
  const [loading, setLoading] = useState(true)
  const toast = useToast()

  const load = useCallback(async () => {
    setLoading(true)
    try { setScan(await api.importScan()) }
    catch (e) { toast(e instanceof Error ? e.message : 'Could not read the import data', 'error') }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { void load() }, [load])

  return (
    <>
      <TopBar title="Import" onMenu={onMenu} />
      <div className="content">
        {loading ? (
          <div className="empty"><span className="spin" /></div>
        ) : !scan?.mounted ? (
          <div className="empty">
            <span className="glyph">📥</span>
            Nothing is mounted at <span className="mono">/import</span>.<br />
            <span className="hint">
              To move users and shares over from CasaOS or another Samba server, follow
              "Migrating from CasaOS" in the README: stop the old smbd, copy
              <span className="mono"> /etc/samba</span> and <span className="mono">/var/lib/samba</span> into
              <span className="mono"> ./import</span>, mount it read-only, and come back here.
            </span>
          </div>
        ) : (
          <>
            <div className="notice accent">
              Import <strong>users first</strong>, then the shares that use them. Users keep their
              old SMB password: only its hash is copied, inside the container, and it is never
              shown here. Nothing is imported until you click it.
            </div>

            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-head"><span className="card-title">Users in the old password database</span></div>
              {scan.users_error && <div className="notice danger">{scan.users_error}</div>}
              {scan.users.length === 0 ? <div className="hint">No users found.</div> : (
                <div className="stack" style={{ gap: 6 }}>
                  {scan.users.map((u) => (
                    <div className="row" key={u.username}>
                      <span className="mono">{u.username}</span>
                      <span className="spacer" />
                      {u.exists ? <span className="badge ok">imported</span> : (
                        <button className="btn sm primary" onClick={async () => {
                          try { await api.importUser(u.username); toast(`Imported ${u.username}`, 'ok'); void load() }
                          catch (e) { toast(e instanceof Error ? e.message : 'Import failed', 'error') }
                        }}>Import user</button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-head"><span className="card-title">Shares in the old smb.conf</span></div>
              {scan.shares.length === 0 ? <div className="hint">No shares found.</div> : (
                <div className="stack">
                  {scan.shares.map((s) => <ImportShareRow key={s.name} share={s} onDone={load} />)}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </>
  )
}

function ImportShareRow({ share, onDone }: { share: ImportedShare; onDone: () => void }) {
  const [path, setPath] = useState(share.local_path)
  const [ack, setAck] = useState(false)
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  return (
    <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12 }}>
      <div className="row wrap">
        <strong>{share.name}</strong>
        <span className="mono hint">{share.path}</span>
        {share.comment && <span className="hint">{share.comment}</span>}
        <span className="spacer" />
        {share.exists && <span className="badge ok">imported</span>}
      </div>
      <div className="row wrap" style={{ gap: 4, margin: '6px 0' }}>
        {share.all_users && <span className="badge accent">all users{share.all_users === 'ro' ? ' (r)' : ''}</span>}
        {share.members.map((m) => (
          <span key={m.username} className="badge">{m.username}{m.access === 'ro' ? ' (r)' : ''}</span>
        ))}
      </div>
      {share.was_anonymous && (
        <div className="notice warn">
          <strong>Was anonymous</strong> (guest, no password). After import it requires an SMB
          login, because anonymous access is switched off.
        </div>
      )}
      {share.notes.map((n) => <div key={n} className="hint">Note: {n}</div>)}
      {!share.exists && share.problems.map((p) => <div key={p} className="notice danger">{p}</div>)}
      {!share.exists && (
        <div className="row wrap" style={{ marginTop: 8 }}>
          <input className="input" style={{ width: 280 }} value={path}
                 placeholder="Folder here, e.g. /files/Photos"
                 onChange={(e) => setPath(e.target.value)} />
          {share.was_anonymous && (
            <label className="check">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              <span>I understand it will require a login</span>
            </label>
          )}
          <button className="btn sm primary" disabled={busy || (share.was_anonymous && !ack)}
                  onClick={async () => {
                    setBusy(true)
                    try {
                      await api.importShare(share.name, path || null, ack)
                      toast(`Imported share ${share.name}`, 'ok'); onDone()
                    } catch (e) {
                      toast(e instanceof Error ? e.message : 'Import failed', 'error')
                    } finally { setBusy(false) }
                  }}>Import share</button>
        </div>
      )}
    </div>
  )
}
