import { useEffect, useState } from 'react'
import { Access, api, Share, ShareMember, User } from '../lib/api'
import { Modal } from './Modal'
import { useToast } from './Toast'

interface Props {
  path: string
  suggestedName: string
  existing?: Share
  /** Load the existing share by id (used from the file browser's "Edit share"). */
  shareId?: string
  fsType?: string
  noUnixPerms?: boolean
  onClose: () => void
  onDone: (share: Share) => void
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/

/** The "Share via SMB" dialog: name, who gets access, and how. */
export function ShareDialog(props: Props) {
  const { path, suggestedName, shareId, onClose, onDone } = props
  const [existing, setExisting] = useState<Share | undefined>(props.existing)
  const [users, setUsers] = useState<User[]>([])
  const [name, setName] = useState(props.existing?.name ?? suggestedName)
  const [comment, setComment] = useState(props.existing?.comment ?? '')
  const [allUsers, setAllUsers] = useState<Access | null>(props.existing?.all_users ?? null)
  const [members, setMembers] = useState<ShareMember[]>(props.existing?.members ?? [])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const toast = useToast()

  useEffect(() => { api.users().then((r) => setUsers(r.users)).catch(() => {}) }, [])

  useEffect(() => {
    if (!shareId || props.existing) return
    api.shares().then((r) => {
      const s = r.shares.find((x) => x.id === shareId)
      if (!s) return
      setExisting(s); setName(s.name); setComment(s.comment)
      setAllUsers(s.all_users); setMembers(s.members)
    }).catch(() => {})
  }, [shareId, props.existing])

  const noUnixPerms = existing?.no_unix_perms ?? props.noUnixPerms ?? false
  const fsType = existing?.fs_type ?? props.fsType ?? ''

  function toggle(username: string) {
    setMembers((current) => current.some((m) => m.username === username)
      ? current.filter((m) => m.username !== username)
      : [...current, { username, access: 'rw' }])
  }

  function setAccess(username: string, access: Access) {
    setMembers((current) => current.map((m) =>
      m.username === username ? { ...m, access } : m))
  }

  async function submit() {
    setBusy(true); setError(null)
    try {
      const share = existing
        ? await api.updateShare(existing.id, { members, all_users: allUsers, comment: comment.trim() })
        : await api.createShare({ path, name: name.trim(), members, all_users: allUsers, comment: comment.trim() })
      toast(existing ? `Updated “${share.name}”` : `Sharing “${share.name}”`, 'ok')
      onDone(share)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not share this folder')
    } finally { setBusy(false) }
  }

  const nobody = allUsers === null && members.length === 0
  const nameOk = !!existing || NAME_RE.test(name.trim())

  return (
    <Modal
      title={existing ? `Edit share “${existing.name}”` : 'Share via SMB'}
      subtitle={path}
      onClose={onClose}
      actions={<>
        <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button className="btn primary" onClick={submit} disabled={busy || !nameOk || nobody}>
          {busy ? <span className="spin" /> : existing ? 'Save changes' : 'Share folder'}
        </button>
      </>}
    >
      {!existing && (
        <div className="field">
          <label htmlFor="share-name">Share name</label>
          <input id="share-name" className="input" value={name} maxLength={64}
                 onChange={(e) => setName(e.target.value)} />
          <span className="hint">
            Letters, digits, space, <span className="mono">. _ -</span>. Clients see it
            as <span className="mono">smb://{location.hostname}/{name || '…'}</span>
          </span>
        </div>
      )}

      {noUnixPerms && (
        <div className="notice warn">
          This folder is on a <strong>{fsType || 'non-unix'}</strong> filesystem, which has no
          unix permissions. Access is enforced by Samba <strong>at share level only</strong>:
          the members below decide who can connect and who can write, but there are no
          per-file permissions inside the share, and anything else that can reach the disk is
          not restricted by these settings.
        </div>
      )}

      <div className="field">
        <label htmlFor="share-comment">Description <span style={{ fontWeight: 400 }}>(optional)</span></label>
        <input id="share-comment" className="input" value={comment} maxLength={256}
               onChange={(e) => setComment(e.target.value)}
               placeholder="Shown to clients browsing the server" />
      </div>

      <div className="field">
        <label>Who has access</label>
        {users.length === 0 ? (
          <div className="notice">
            No SMB users yet. Create one on the <strong>Users</strong> page, then come back.
          </div>
        ) : (
          <div className="stack" style={{ gap: 6 }}>
            {users.map((u) => {
              const member = members.find((m) => m.username === u.username)
              return (
                <div className="row" key={u.username}
                     style={{
                       padding: '7px 10px', borderRadius: 8,
                       border: '1px solid var(--border)',
                       background: member ? 'var(--accent-soft)' : 'transparent',
                     }}>
                  <label className="check" style={{ flex: 1, minWidth: 0 }}>
                    <input type="checkbox" checked={!!member}
                           onChange={() => toggle(u.username)} />
                    <span className="truncate">
                      {u.display_name}
                      {u.display_name !== u.username &&
                        <span className="hint"> ({u.username})</span>}
                    </span>
                  </label>
                  {member && (
                    <select className="select" style={{ width: 'auto' }}
                            value={member.access}
                            onChange={(e) => setAccess(u.username, e.target.value as Access)}>
                      <option value="rw">Read &amp; write</option>
                      <option value="ro">Read-only</option>
                    </select>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div className="field">
        <label htmlFor="share-all">All users of this server</label>
        <select id="share-all" className="select" value={allUsers ?? 'off'}
                onChange={(e) => setAllUsers(e.target.value === 'off' ? null : e.target.value as Access)}>
          <option value="off">Off: only the people ticked above</option>
          <option value="ro">Every SMB user of this server: read-only</option>
          <option value="rw">Every SMB user of this server: read &amp; write</option>
        </select>
        <span className="hint">
          This is not guest access: a login is always required. Anonymous access is switched
          off server-wide, so a device that used to connect without a password needs an SMB
          user account.
        </span>
      </div>

      {nobody && (
        <div className="notice warn">
          Tick at least one person (or allow all users of this server). A share nobody can
          reach is not allowed.
        </div>
      )}

      {error && <div className="notice danger">{error}</div>}
    </Modal>
  )
}
