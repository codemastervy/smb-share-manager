import { useCallback, useEffect, useState } from 'react'
import { TopBar } from '../App'
import { api, PermissionPlan, SambaStatus, Share } from '../lib/api'
import { when } from '../lib/format'
import { Modal } from '../components/Modal'
import { ShareDialog } from '../components/ShareDialog'
import { useToast } from '../components/Toast'

export function Shares({ onMenu }: { onMenu: () => void }) {
  const [shares, setShares] = useState<Share[]>([])
  const [status, setStatus] = useState<SambaStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState<Share | null>(null)
  const [confirm, setConfirm] = useState<Share | null>(null)
  const [config, setConfig] = useState<string | null>(null)
  const [perms, setPerms] = useState<{ share: Share; plan: PermissionPlan } | null>(null)
  const [fixTicked, setFixTicked] = useState(false)
  const toast = useToast()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const result = await api.shares()
      setShares(result.shares); setStatus(result.status)
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not load shares', 'error')
    } finally { setLoading(false) }
  }, [toast])

  useEffect(() => { void load() }, [load])

  async function unshare(share: Share) {
    try {
      await api.deleteShare(share.id)
      toast(`“${share.name}” is no longer shared`, 'ok')
      void load()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not unshare', 'error')
    }
  }

  const hostHint = window.location.hostname

  return (
    <>
      <TopBar title="Shares" onMenu={onMenu}>
        {status && (
          <span className={`badge ${status.running ? 'ok' : 'danger'}`}>
            <span className="dot" />Samba {status.running ? 'running' : 'not responding'}
          </span>
        )}
        <button className="btn sm" onClick={async () => {
          try { setConfig((await api.shareConfig()).content) }
          catch { toast('Could not read the generated config', 'error') }
        }}>View config</button>
      </TopBar>

      <div className="content">
        <div className="notice accent">
          <strong>Nothing is shared automatically.</strong> A folder becomes
          reachable over SMB only when you explicitly share it — right-click any
          folder in <strong>Files</strong> and choose “Share via SMB”. Removing a
          share here revokes access immediately.
        </div>

        {status && (status.missing_shares.length > 0 || status.extra_shares.length > 0
                    || status.missing_users.length > 0 || status.extra_users.length > 0) && (
          <div className="notice warn">
            <strong>Samba does not agree with the registry.</strong>
            {status.missing_shares.length > 0 && <> Not live: {status.missing_shares.join(', ')}.</>}
            {status.extra_shares.length > 0 && <> Live but unknown: {status.extra_shares.join(', ')}.</>}
            {status.missing_users.length > 0 && <> Users missing in Samba: {status.missing_users.join(', ')}.</>}
            {status.extra_users.length > 0 && <> Unknown Samba users: {status.extra_users.join(', ')}.</>}
            {' '}<button className="btn sm" onClick={async () => {
              try { await api.reapply(); toast('Configuration re-applied', 'ok'); void load() }
              catch (e) { toast(e instanceof Error ? e.message : 'Could not re-apply', 'error') }
            }}>Re-apply configuration</button>
          </div>
        )}
        {status && !status.running && status.detail && (
          <div className="notice danger">{status.detail}</div>
        )}

        {loading ? (
          <div className="empty"><span className="spin" /></div>
        ) : shares.length === 0 ? (
          <div className="empty">
            <span className="glyph">🔗</span>
            No folders are shared.<br />
            <span className="hint">
              That is the default. Go to <strong>Files</strong>, right-click a
              folder, and choose “Share via SMB”.
            </span>
          </div>
        ) : (
          <div className="card" style={{ padding: 0, overflowX: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Share</th>
                  <th>Folder</th>
                  <th>Access</th>
                  <th>Who</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {shares.map((share) => {
                  const live = status?.active_shares.includes(share.name)
                  return (
                    <tr key={share.id}>
                      <td>
                        <div className="row">
                          <strong>{share.name}</strong>
                          {live === false && <span className="badge warn">not live</span>}
                        </div>
                        <div className="mono" style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
                          smb://{hostHint}/{share.name}
                        </div>
                        {share.comment && <div className="hint">{share.comment}</div>}
                      </td>
                      <td>
                        <div className="mono truncate" style={{ maxWidth: 240 }}>{share.real_path}</div>
                        {share.no_unix_perms && (
                          <span className="badge" title="No unix permissions: access is enforced by Samba at share level only">
                            {share.fs_type}: share-level access only
                          </span>
                        )}
                      </td>
                      <td>
                        {share.all_users === 'rw' || share.members.some((m) => m.access === 'rw')
                          ? <span className="badge ok">read &amp; write</span>
                          : <span className="badge warn">read-only</span>}
                      </td>
                      <td>
                        <div className="row wrap" style={{ gap: 4 }}>
                          {share.all_users && (
                            <span className="badge accent" title="Every SMB user of this server (login required)">
                              all users{share.all_users === 'ro' ? ' (r)' : ''}
                            </span>
                          )}
                          {share.members.map((m) => (
                            <span key={m.username} className="badge"
                                  title={m.access === 'ro' ? 'read-only' : 'read & write'}>
                              {m.username}{m.access === 'ro' ? ' (r)' : ''}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="hint">{when(share.created_at)}</td>
                      <td>
                        <div className="row">
                          <button className="btn sm" onClick={() => setEditing(share)}>Edit</button>
                          {!share.no_unix_perms && (
                            <button className="btn sm" onClick={async () => {
                              try { setFixTicked(false); setPerms({ share, plan: await api.permissionPlan(share.id) }) }
                              catch (e) { toast(e instanceof Error ? e.message : 'Could not check permissions', 'error') }
                            }}>Permissions</button>
                          )}
                          <button className="btn sm danger" onClick={() => setConfirm(share)}>Unshare</button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing && (
        <ShareDialog path={editing.path} suggestedName={editing.name} existing={editing}
                     onClose={() => setEditing(null)}
                     onDone={() => { setEditing(null); void load() }} />
      )}

      {confirm && (
        <Modal title={`Unshare “${confirm.name}”?`}
               subtitle="Access is revoked immediately. The folder and its contents are not touched."
               onClose={() => setConfirm(null)}
               actions={<>
                 <button className="btn" onClick={() => setConfirm(null)}>Cancel</button>
                 <button className="btn danger" onClick={() => { void unshare(confirm); setConfirm(null) }}>
                   Unshare
                 </button>
               </>}>
          <div className="notice">
            <span className="mono">{confirm.path}</span> stops being reachable at{' '}
            <span className="mono">smb://{hostHint}/{confirm.name}</span>. Anyone
            currently connected to it is disconnected.
          </div>
        </Modal>
      )}

      {perms && (
        <Modal title={`Folder permissions for “${perms.share.name}”`}
               subtitle={perms.plan.path}
               onClose={() => setPerms(null)}
               actions={perms.plan.changes.length === 0
                 ? <button className="btn primary" onClick={() => setPerms(null)}>Close</button>
                 : <>
                   <button className="btn" onClick={() => setPerms(null)}>Cancel</button>
                   <button className="btn primary" disabled={!fixTicked} onClick={async () => {
                     try {
                       await api.applyPermissions(perms.share.id, perms.plan.before)
                       toast('Permissions updated', 'ok')
                     } catch (e) {
                       toast(e instanceof Error ? e.message : 'Permissions not changed', 'error')
                     }
                     setPerms(null)
                   }}>Apply</button>
                 </>}>
          {perms.plan.changes.length === 0 ? (
            <div className="notice">Permissions look right; nothing to change.</div>
          ) : (
            <>
              <div className="notice">
                SMB users can only write here if the folder belongs to the
                <span className="mono"> smbusers</span> group and is group-writable. These
                changes would be made to this folder itself only, never to anything inside it:
              </div>
              <ul className="mono" style={{ margin: '0 0 12px', paddingLeft: 18 }}>
                {perms.plan.changes.map((c) => <li key={c}>{c}</li>)}
              </ul>
              <label className="check">
                <input type="checkbox" checked={fixTicked}
                       onChange={(e) => setFixTicked(e.target.checked)} />
                <span>Fix permissions as listed above</span>
              </label>
            </>
          )}
        </Modal>
      )}

      {config !== null && (
        <Modal title="Generated Samba configuration"
               subtitle="What Samba is running now (testparm -s), rebuilt from the share registry on every change."
               onClose={() => setConfig(null)}
               actions={<button className="btn primary" onClick={() => setConfig(null)}>Close</button>}>
          <pre className="mono" style={{
            background: 'var(--bg-inset)', padding: 12, borderRadius: 8,
            maxHeight: '52vh', overflow: 'auto', margin: 0, whiteSpace: 'pre-wrap',
          }}>{config}</pre>
        </Modal>
      )}
    </>
  )
}
