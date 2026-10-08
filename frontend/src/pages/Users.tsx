import { useCallback, useEffect, useState } from 'react'
import { TopBar } from '../App'
import { api, User } from '../lib/api'
import { when } from '../lib/format'
import { Modal } from '../components/Modal'
import { useToast } from '../components/Toast'

export function Users({ onMenu }: { onMenu: () => void }) {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<User | null>(null)
  const [confirm, setConfirm] = useState<User | null>(null)
  const toast = useToast()

  const load = useCallback(async () => {
    setLoading(true)
    try { setUsers((await api.users()).users) }
    catch (e) { toast(e instanceof Error ? e.message : 'Could not load users', 'error') }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { void load() }, [load])

  const host = window.location.hostname

  return (
    <>
      <TopBar title="Users" onMenu={onMenu}>
        <button className="btn sm primary" onClick={() => setAdding(true)}>Add user</button>
      </TopBar>

      <div className="content">
        <div className="notice">
          These are <strong>SMB accounts</strong>, used by family members to
          connect from Finder, Windows Explorer, or a phone's SMB client. They
          are not logins for this web page, and they cannot log in to a shell — each one
          is created with <span className="mono">nologin</span> and no home directory.
        </div>

        {loading ? (
          <div className="empty"><span className="spin" /></div>
        ) : users.length === 0 ? (
          <div className="empty">
            <span className="glyph">👥</span>
            No SMB users yet.<br />
            <span className="hint">Add one, then grant it access when you share a folder.</span>
          </div>
        ) : (
          <div className="card" style={{ padding: 0, overflowX: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th><th>Username</th><th>Shares</th><th>Created</th><th></th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.username}>
                    <td><strong>{u.display_name}</strong></td>
                    <td className="mono">{u.username}</td>
                    <td>
                      {!u.shares?.length ? <span className="hint">none</span> : (
                        <div className="row wrap" style={{ gap: 4 }}>
                          {u.shares.map((s) => (
                            <span key={s.id} className="badge">
                              {s.name}{s.access === 'ro' ? ' (r)' : ''}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="hint">{when(u.created_at)}</td>
                    <td>
                      <div className="row">
                        <button className="btn sm" onClick={() => setEditing(u)}>Edit</button>
                        <button className="btn sm danger" onClick={() => setConfirm(u)}>Remove</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {users.length > 0 && (
          <div className="notice" style={{ marginTop: 16 }}>
            <strong>How family members connect.</strong> On a Mac, Finder →{' '}
            <span className="mono">⌘K</span> → <span className="mono">smb://{host}/ShareName</span>.
            On Windows, Explorer → <span className="mono">\\{host}\ShareName</span>.
            On a phone, any SMB client pointed at <span className="mono">{host}</span>,
            using the username and password set here.
          </div>
        )}
      </div>

      {(adding || editing) && (
        <UserDialog user={editing}
                    onClose={() => { setAdding(false); setEditing(null) }}
                    onDone={() => { setAdding(false); setEditing(null); void load() }} />
      )}

      {confirm && (
        <Modal title={`Remove ${confirm.display_name}?`}
               subtitle="The account is deleted and removed from every share it can reach."
               onClose={() => setConfirm(null)}
               actions={<>
                 <button className="btn" onClick={() => setConfirm(null)}>Cancel</button>
                 <button className="btn danger" onClick={async () => {
                   try {
                     const result = await api.deleteUser(confirm.username)
                     toast(result.removed_from_shares.length
                       ? `Removed, and revoked from ${result.removed_from_shares.join(', ')}`
                       : 'User removed', 'ok')
                     void load()
                   } catch (e) {
                     toast(e instanceof Error ? e.message : 'Could not remove user', 'error')
                   }
                   setConfirm(null)
                 }}>Remove</button>
               </>}>
          {confirm.shares?.length ? (
            <div className="notice warn">
              This user currently has access to{' '}
              <strong>{confirm.shares.map((s) => s.name).join(', ')}</strong>.
              That access is revoked as part of removing them.
            </div>
          ) : null}
        </Modal>
      )}
    </>
  )
}

function UserDialog({ user, onClose, onDone }: {
  user: User | null; onClose: () => void; onDone: () => void
}) {
  const [username, setUsername] = useState(user?.username ?? '')
  const [displayName, setDisplayName] = useState(user?.display_name ?? '')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const toast = useToast()

  async function submit() {
    setBusy(true); setError(null)
    try {
      if (user) {
        await api.updateUser(user.username, {
          display_name: displayName,
          ...(password ? { password } : {}),
        })
        toast('User updated', 'ok')
      } else {
        await api.createUser({ username: username.trim().toLowerCase(), password, display_name: displayName })
        toast('User created', 'ok')
      }
      onDone()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the user')
    } finally { setBusy(false) }
  }

  return (
    <Modal title={user ? `Edit ${user.username}` : 'Add SMB user'}
           onClose={onClose}
           actions={<>
             <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
             <button className="btn primary" onClick={submit}
                     disabled={busy || (!user && (!username.trim() || !password))}>
               {busy ? <span className="spin" /> : user ? 'Save' : 'Create user'}
             </button>
           </>}>
      {!user && (
        <div className="field">
          <label htmlFor="u-name">Username</label>
          <input id="u-name" className="input" value={username} autoFocus
                 onChange={(e) => setUsername(e.target.value)} placeholder="e.g. sam" />
          <span className="hint">
            Lowercase letters, digits, <span className="mono">-</span> and{' '}
            <span className="mono">_</span>. This is what they type when connecting.
          </span>
        </div>
      )}

      <div className="field">
        <label htmlFor="u-display">Display name</label>
        <input id="u-display" className="input" value={displayName}
               onChange={(e) => setDisplayName(e.target.value)}
               placeholder="Shown in this web page only" />
      </div>

      <div className="field">
        <label htmlFor="u-pass">{user ? 'New password (leave blank to keep)' : 'Password'}</label>
        <input id="u-pass" className="input" type="password" value={password}
               autoComplete="new-password"
               onChange={(e) => setPassword(e.target.value)} />
        <span className="hint">At least 10 characters.</span>
      </div>

      {error && <div className="notice danger">{error}</div>}
    </Modal>
  )
}
