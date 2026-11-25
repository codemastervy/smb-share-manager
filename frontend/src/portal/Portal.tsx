import { DragEvent, useCallback, useEffect, useRef, useState } from 'react'
import { ContextMenu, MenuItem } from '../components/ContextMenu'
import { Icon } from '../components/Icon'
import { Modal } from '../components/Modal'
import { ToastHost, useToast } from '../components/Toast'
import { bytes, fileDate, iconFor } from '../lib/format'
import { Listing, Me, PortalEntry, PortalError, portal } from './api'

/** Where we are: '' is the list of shares, otherwise '/Share/sub/folder'. Kept in ?p= so
 *  back/forward and reloads work, and a share can't collide with /api or /assets. */
function readLocation(): string {
  const p = new URLSearchParams(window.location.search).get('p') ?? ''
  return p.startsWith('/') && p.length > 1 ? p.replace(/\/+$/, '') : ''
}

export function Portal() {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('ssm-theme') ?? 'dark' } catch { return 'dark' }
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('ssm-theme', theme) } catch { /* private mode */ }
  }, [theme])

  const [me, setMe] = useState<Me | null>(null)
  const [fatal, setFatal] = useState<string | null>(null)

  useEffect(() => {
    portal.me().then(setMe).catch((e) => setFatal(e instanceof Error ? e.message : 'Unavailable'))
  }, [])

  return (
    <ToastHost>
      <div className="portal">
        <header className="topbar">
          <span className="brand">
            <span className="brand-mark"><Icon name="folder" size={15} /></span>
            <span>Files</span>
          </span>
          <div className="spacer" />
          {me && <span className="portal-user">{me.email}</span>}
          <button className="btn ghost icon" aria-label="Switch theme"
                  title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
                  onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
          </button>
        </header>

        <main className="portal-wrap">
          {fatal ? (
            <div className="empty">
              <span className="glyph"><Icon name="server" size={30} /></span>
              {fatal}
            </div>
          ) : !me ? (
            <div style={{ display: 'grid', placeItems: 'center', padding: 60 }}><span className="spin" /></div>
          ) : (
            <Browser me={me} />
          )}
        </main>
        <footer className="portal-foot">Files are downloaded, never opened in this page.</footer>
      </div>
    </ToastHost>
  )
}

interface Upload { id: number; name: string; progress: number; error?: string }

function Browser({ me }: { me: Me }) {
  const [path, setPath] = useState(readLocation)
  const [listing, setListing] = useState<Listing | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [menu, setMenu] = useState<{ x: number; y: number; entry: PortalEntry } | null>(null)
  const [dialog, setDialog] = useState<
    { kind: 'mkdir' } | { kind: 'rename'; entry: PortalEntry } | { kind: 'delete'; entry: PortalEntry } | null
  >(null)
  const [uploads, setUploads] = useState<Upload[]>([])
  const [dragging, setDragging] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)
  const toast = useToast()

  const go = useCallback((next: string) => {
    const url = next ? `?p=${encodeURIComponent(next)}` : window.location.pathname
    window.history.pushState(null, '', url)
    setPath(next)
  }, [])

  useEffect(() => {
    const onPop = () => setPath(readLocation())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  const load = useCallback(async () => {
    if (!path) { setListing(null); setError(null); return }
    setLoading(true)
    try {
      setListing(await portal.list(path)); setError(null)
    } catch (e) {
      setListing(null)
      setError(e instanceof PortalError && e.status === 404
        ? 'This folder does not exist or is not shared with you.'
        : e instanceof Error ? e.message : 'Could not open this folder')
    } finally { setLoading(false) }
  }, [path])

  useEffect(() => { void load() }, [load])

  const canWrite = listing?.access === 'rw'

  async function uploadFiles(files: FileList | File[]) {
    if (!listing || !canWrite) return
    const dir = listing.path
    for (const file of Array.from(files)) {
      const id = Date.now() + Math.random()
      if (file.size > me.max_upload_bytes) {
        setUploads((u) => [...u, { id, name: file.name, progress: 0, error: `larger than ${bytes(me.max_upload_bytes)}` }])
        continue
      }
      setUploads((u) => [...u, { id, name: file.name, progress: 0 }])
      try {
        const res = await portal.upload(dir, file, (f) =>
          setUploads((u) => u.map((x) => (x.id === id ? { ...x, progress: f } : x))))
        setUploads((u) => u.filter((x) => x.id !== id))
        toast(res.name === file.name ? `Uploaded ${file.name}` : `Uploaded as ${res.name}`, 'ok')
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'failed'
        setUploads((u) => u.map((x) => (x.id === id ? { ...x, error: msg } : x)))
      }
    }
    void load()
  }

  function onDrop(e: DragEvent) {
    e.preventDefault(); setDragging(false)
    if (e.dataTransfer.files.length) void uploadFiles(e.dataTransfer.files)
  }

  function open(entry: PortalEntry) {
    if (!listing) return
    const target = `${listing.path}/${entry.name}`
    if (entry.is_dir) go(target)
    else window.location.href = portal.downloadUrl(target)
  }

  function menuItems(entry: PortalEntry): MenuItem[] {
    const items: MenuItem[] = [
      { label: entry.is_dir ? 'Open' : 'Download', icon: entry.is_dir ? 'folder' : 'download', onSelect: () => open(entry) },
    ]
    if (canWrite) {
      items.push(
        { label: 'Rename…', icon: 'pencil', onSelect: () => setDialog({ kind: 'rename', entry }) },
        { label: 'Delete…', icon: 'trash', danger: true, separatorBefore: true,
          onSelect: () => setDialog({ kind: 'delete', entry }) },
      )
    }
    return items
  }

  // ------------------------------------------------------------ the list of shares
  if (!path) {
    return (
      <>
        <div className="hero">
          <h2>Your shared folders</h2>
          <p>Signed in as {me.email}. Open a folder to browse, download or upload.</p>
        </div>
        {me.shares.length === 0 ? (
          <div className="empty">
            <span className="glyph"><Icon name="folder" size={30} /></span>
            No folders are shared with you over the internet yet.
          </div>
        ) : (
          <div className="share-grid">
            {me.shares.map((s) => (
              <button key={s.name} className="share-card" onClick={() => go(`/${s.name}`)}>
                <span className="glyph-box"><Icon name="folder" size={22} /></span>
                <span>
                  <strong>{s.name}</strong>
                  <span className="sub">{s.access === 'rw' ? 'Read & write' : 'Read only'}</span>
                </span>
              </button>
            ))}
          </div>
        )}
      </>
    )
  }

  // ------------------------------------------------------------ inside a share
  const crumbs = path.split('/').filter(Boolean)
  return (
    <div className={`drop-target ${dragging ? 'dragging' : ''}`}
         onDragOver={(e) => { if (canWrite) { e.preventDefault(); setDragging(true) } }}
         onDragLeave={(e) => { if (e.currentTarget === e.target) setDragging(false) }}
         onDrop={onDrop}>
      <div className="browser-bar">
        <div className="crumbs">
          <button className="crumb" onClick={() => go('')}>Home</button>
          {crumbs.map((part, i) => {
            const target = '/' + crumbs.slice(0, i + 1).join('/')
            return (
              <span key={target} className="row" style={{ gap: 3 }}>
                <span className="crumb-sep">/</span>
                <button className={`crumb ${i === crumbs.length - 1 ? 'current' : ''}`}
                        onClick={() => go(target)}>{part}</button>
              </span>
            )
          })}
        </div>
        <span className="spacer" style={{ flex: 1 }} />
        {listing && !canWrite && <span className="badge">read only</span>}
        <button className="btn sm ghost icon" onClick={() => void load()} title="Refresh" aria-label="Refresh">
          <Icon name="refresh" />
        </button>
        {canWrite && (
          <>
            <button className="btn sm" onClick={() => setDialog({ kind: 'mkdir' })}>New folder</button>
            <button className="btn sm primary" onClick={() => fileInput.current?.click()}>
              <Icon name="upload" size={15} /> Upload
            </button>
            <input ref={fileInput} type="file" multiple hidden
                   onChange={(e) => { if (e.target.files) void uploadFiles(e.target.files); e.target.value = '' }} />
          </>
        )}
      </div>

      {loading && !listing ? (
        <div style={{ display: 'grid', placeItems: 'center', padding: 40 }}><span className="spin" /></div>
      ) : error ? (
        <div className="notice danger">{error}</div>
      ) : listing && listing.entries.length === 0 ? (
        <div className="empty">
          <span className="glyph"><Icon name="folder" size={30} /></span>
          This folder is empty.{canWrite && <><br />Drop files here or use Upload.</>}
        </div>
      ) : listing && (
        <div className="file-list">
          {listing.entries.map((entry) => (
            <div key={entry.name} className="file-row" onDoubleClick={() => open(entry)}
                 onContextMenu={(e) => { e.preventDefault(); setMenu({ x: e.clientX, y: e.clientY, entry }) }}>
              <Icon name={iconFor(entry)} size={17} />
              <span className="name">
                <button onClick={() => open(entry)}>{entry.name}</button>
              </span>
              <span className="size">{entry.is_dir ? '—' : bytes(entry.size)}</span>
              <span className="date">{fileDate(entry.modified)}</span>
              <button className="btn ghost icon" aria-label={`Actions for ${entry.name}`}
                      onClick={(e) => setMenu({ x: e.clientX, y: e.clientY, entry })}>⋯</button>
            </div>
          ))}
        </div>
      )}

      {menu && <ContextMenu x={menu.x} y={menu.y} items={menuItems(menu.entry)} onClose={() => setMenu(null)} />}

      {dialog && listing && (
        <NameDialog dialog={dialog} dir={listing.path} onClose={() => setDialog(null)}
                    onDone={(msg) => { setDialog(null); toast(msg, 'ok'); void load() }} />
      )}

      {uploads.length > 0 && (
        <div className="uploads" role="status">
          {uploads.map((u) => (
            <div key={u.id} className={`up ${u.error ? 'failed' : ''}`}>
              <div className="row">
                <span className="truncate">{u.name}</span>
                {u.error
                  ? <button className="btn sm ghost" onClick={() => setUploads((x) => x.filter((y) => y.id !== u.id))}>Dismiss</button>
                  : <span>{Math.round(u.progress * 100)}%</span>}
              </div>
              {u.error ? <span>{u.error}</span>
                : <div className="progress-strip"><span style={{ width: `${u.progress * 100}%` }} /></div>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function NameDialog({ dialog, dir, onClose, onDone }: {
  dialog: { kind: 'mkdir' } | { kind: 'rename'; entry: PortalEntry } | { kind: 'delete'; entry: PortalEntry }
  dir: string
  onClose: () => void
  onDone: (message: string) => void
}) {
  const [name, setName] = useState(dialog.kind === 'rename' ? dialog.entry.name : '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit() {
    setBusy(true); setError(null)
    try {
      if (dialog.kind === 'mkdir') {
        await portal.mkdir(dir, name.trim()); onDone(`Created ${name.trim()}`)
      } else if (dialog.kind === 'rename') {
        await portal.rename(`${dir}/${dialog.entry.name}`, name.trim()); onDone('Renamed')
      } else {
        await portal.remove(`${dir}/${dialog.entry.name}`); onDone(`Deleted ${dialog.entry.name}`)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed')
    } finally { setBusy(false) }
  }

  const title = dialog.kind === 'mkdir' ? 'New folder'
    : dialog.kind === 'rename' ? `Rename ${dialog.entry.name}` : `Delete ${dialog.entry.name}?`
  return (
    <Modal title={title} onClose={onClose}
           actions={<>
             <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
             <button className={`btn ${dialog.kind === 'delete' ? 'danger' : 'primary'}`} onClick={submit}
                     disabled={busy || (dialog.kind !== 'delete' && !name.trim())}>
               {busy ? <span className="spin" /> : dialog.kind === 'delete' ? 'Delete' : 'Save'}
             </button>
           </>}>
      {dialog.kind === 'delete' ? (
        <p>
          {dialog.entry.is_dir
            ? 'The folder and everything inside it will be deleted for everyone who uses this share.'
            : 'The file will be deleted for everyone who uses this share.'} This can't be undone.
        </p>
      ) : (
        <div className="field">
          <label htmlFor="p-name">Name</label>
          <input id="p-name" className="input" value={name} autoFocus spellCheck={false}
                 onChange={(e) => setName(e.target.value)}
                 onKeyDown={(e) => { if (e.key === 'Enter' && name.trim()) void submit() }} />
        </div>
      )}
      {error && <div className="notice danger">{error}</div>}
    </Modal>
  )
}
