import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { TopBar } from '../App'
import { api, Entry, Listing, uploadFile, Volume } from '../lib/api'
import { bytes, fileDate, iconFor } from '../lib/format'
import { ContextMenu, MenuItem, useLongPress } from '../components/ContextMenu'
import { Modal } from '../components/Modal'
import { ShareDialog } from '../components/ShareDialog'
import { useToast } from '../components/Toast'

type SortKey = 'name' | 'size' | 'modified' | 'type'
type ViewMode = 'list' | 'grid'

interface Upload { id: number; name: string; progress: number; error?: string }

export function Files({ onMenu }: { onMenu: () => void }) {
  const navigate = useNavigate()
  const location = useLocation()

  // The browsed path lives in the URL, so a deep link and the browser's back
  // button both work the way people expect.
  const path = decodeURIComponent(location.pathname.replace(/^\/files/, '')) || ''

  const [volumes, setVolumes] = useState<Volume[]>([])
  const [listing, setListing] = useState<Listing | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [view, setView] = useState<ViewMode>(
    () => (localStorage.getItem('ssm-view') as ViewMode) ?? 'list')
  const [sortKey, setSortKey] = useState<SortKey>(
    () => (localStorage.getItem('ssm-sort') as SortKey) ?? 'name')
  const [ascending, setAscending] = useState(
    () => localStorage.getItem('ssm-asc') !== 'false')
  const [showHidden, setShowHidden] = useState(false)

  const [query, setQuery] = useState('')
  const [searching, setSearching] = useState(false)

  const [menu, setMenu] = useState<{ x: number; y: number; entry: Entry | null } | null>(null)
  const [renaming, setRenaming] = useState<Entry | null>(null)
  const [newFolder, setNewFolder] = useState(false)
  const [sharing, setSharing] = useState<{ path: string; name: string; shareId?: string } | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<string[] | null>(null)
  const [clipboard, setClipboard] = useState<{ mode: 'copy' | 'cut'; paths: string[] } | null>(null)
  const [uploads, setUploads] = useState<Upload[]>([])

  const fileInput = useRef<HTMLInputElement>(null)
  const toast = useToast()

  useEffect(() => { localStorage.setItem('ssm-view', view) }, [view])
  useEffect(() => { localStorage.setItem('ssm-sort', sortKey) }, [sortKey])
  useEffect(() => { localStorage.setItem('ssm-asc', String(ascending)) }, [ascending])

  const loadVolumes = useCallback(() => {
    api.volumes().then((r) => setVolumes(r.volumes)).catch((e) => setError(e.message))
  }, [])

  const load = useCallback(async () => {
    if (!path) { setListing(null); return }
    setLoading(true); setError(null)
    try {
      setListing(await api.list(path, showHidden))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not open this folder')
      setListing(null)
    } finally { setLoading(false) }
  }, [path, showHidden])

  useEffect(() => { loadVolumes() }, [loadVolumes])
  useEffect(() => { void load(); setSelected(new Set()); setQuery('') }, [load])

  // Debounced recursive search, so typing doesn't fire a walk per keystroke.
  useEffect(() => {
    if (!query.trim() || !path) { if (searching) { setSearching(false); void load() } return }
    const handle = window.setTimeout(async () => {
      setSearching(true); setLoading(true)
      try { setListing(await api.search(path, query, showHidden)) }
      catch (e) { setError(e instanceof Error ? e.message : 'Search failed') }
      finally { setLoading(false) }
    }, 320)
    return () => window.clearTimeout(handle)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, path, showHidden])

  const go = (to: string) => navigate(`/files${to}`)

  const entries = useMemo(() => {
    const list = [...(listing?.entries ?? [])]
    const direction = ascending ? 1 : -1
    list.sort((a, b) => {
      // Folders always lead, regardless of sort key or direction -- this is
      // what every file manager does and what people expect.
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1
      switch (sortKey) {
        case 'size': return direction * ((a.size ?? 0) - (b.size ?? 0))
        case 'modified': return direction * (a.modified - b.modified)
        case 'type': {
          const ax = a.name.split('.').pop() ?? ''
          const bx = b.name.split('.').pop() ?? ''
          return direction * ax.localeCompare(bx)
        }
        default:
          return direction * a.name.localeCompare(b.name, undefined, { numeric: true })
      }
    })
    return list
  }, [listing, sortKey, ascending])

  function toggleSelect(entryPath: string, additive: boolean) {
    setSelected((current) => {
      const next = additive ? new Set(current) : new Set<string>()
      if (current.has(entryPath) && additive) next.delete(entryPath)
      else next.add(entryPath)
      return next
    })
  }

  function open(entry: Entry) {
    if (entry.is_dir) { go(entry.path); return }
    // Files are only ever downloaded, never opened in the page.
    window.location.href = api.downloadUrl(entry.path)
  }

  // ------------------------------------------------------------ operations

  async function doDelete(paths: string[]) {
    try {
      const result = await api.remove(paths)
      if (result.failed.length) {
        toast(`${result.failed.length} item(s) could not be deleted: ${result.failed[0].error}`, 'error')
      }
      if (result.deleted.length) toast(`Deleted ${result.deleted.length} item(s)`, 'ok')
      setSelected(new Set()); void load(); loadVolumes()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Delete failed', 'error')
    }
  }

  async function paste() {
    if (!clipboard || !path) return
    try {
      const result = clipboard.mode === 'copy'
        ? await api.copy(clipboard.paths, path)
        : await api.move(clipboard.paths, path)
      const failed = result.failed ?? []
      if (failed.length) toast(`${failed.length} item(s) failed: ${failed[0].error}`, 'error')
      else toast(clipboard.mode === 'copy' ? 'Copied' : 'Moved', 'ok')
      if (clipboard.mode === 'cut') setClipboard(null)
      void load()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Paste failed', 'error')
    }
  }

  async function handleFiles(files: FileList | null) {
    if (!files || !path) return
    for (const file of Array.from(files)) {
      const id = Date.now() + Math.random()
      setUploads((u) => [...u, { id, name: file.name, progress: 0 }])
      try {
        await uploadFile(path, file, (fraction) => {
          setUploads((u) => u.map((x) => x.id === id ? { ...x, progress: fraction } : x))
        })
        setUploads((u) => u.filter((x) => x.id !== id))
      } catch (e) {
        setUploads((u) => u.map((x) => x.id === id
          ? { ...x, error: e instanceof Error ? e.message : 'failed' } : x))
        toast(`${file.name}: ${e instanceof Error ? e.message : 'upload failed'}`, 'error')
      }
    }
    void load(); loadVolumes()
  }

  // ------------------------------------------------------------ menu

  function menuItems(entry: Entry | null): MenuItem[] {
    const targets = entry
      ? (selected.has(entry.path) ? [...selected] : [entry.path])
      : [...selected]

    if (!entry) {
      return [
        { label: 'New folder', icon: '📁', onSelect: () => setNewFolder(true) },
        { label: 'Upload files', icon: '⬆️', onSelect: () => fileInput.current?.click() },
        {
          label: clipboard ? `Paste ${clipboard.paths.length} item(s)` : 'Paste',
          icon: '📋', disabled: !clipboard, separatorBefore: true,
          onSelect: () => void paste(),
        },
        { label: 'Refresh', icon: '🔄', onSelect: () => void load() },
      ]
    }

    const items: MenuItem[] = []

    if (entry.is_dir) {
      items.push(entry.share
        ? {
          label: `Edit share “${entry.share.name}”`, icon: '🔗',
          onSelect: () => setSharing({ path: entry.path, name: entry.name, shareId: entry.share!.id }),
        }
        : {
          label: 'Share via SMB…', icon: '🔗',
          onSelect: () => setSharing({ path: entry.path, name: entry.name }),
        })
      items.push({ label: 'Open', icon: '📂', onSelect: () => open(entry) })
    } else {
      items.push({ label: 'Download', icon: '⬇️', onSelect: () => { window.location.href = api.downloadUrl(entry.path) } })
    }

    items.push(
      { label: 'Rename', icon: '✏️', separatorBefore: true, disabled: targets.length > 1, onSelect: () => setRenaming(entry) },
      { label: `Copy${targets.length > 1 ? ` (${targets.length})` : ''}`, icon: '📄', onSelect: () => { setClipboard({ mode: 'copy', paths: targets }); toast(`${targets.length} item(s) ready to paste`) } },
      { label: `Cut${targets.length > 1 ? ` (${targets.length})` : ''}`, icon: '✂️', onSelect: () => { setClipboard({ mode: 'cut', paths: targets }); toast(`${targets.length} item(s) ready to move`) } },
      { label: `Delete${targets.length > 1 ? ` (${targets.length})` : ''}`, icon: '🗑️', danger: true, separatorBefore: true, onSelect: () => setConfirmDelete(targets) },
    )
    return items
  }

  // ------------------------------------------------------------ render

  const crumbs = path.split('/').filter(Boolean)

  return (
    <>
      <TopBar title="Files" onMenu={onMenu}>
        <div className="row">
          <button className={`btn sm ${view === 'list' ? 'primary' : ''}`}
                  onClick={() => setView('list')} title="List view">☰</button>
          <button className={`btn sm ${view === 'grid' ? 'primary' : ''}`}
                  onClick={() => setView('grid')} title="Grid view">▦</button>
        </div>
      </TopBar>

      <div className="content"
           onContextMenu={(e) => {
             if ((e.target as HTMLElement).closest('.file-row, .file-tile')) return
             e.preventDefault()
             setMenu({ x: e.clientX, y: e.clientY, entry: null })
           }}>

        {/* ------------------------------------------------ volumes */}
        {!path && (
          <>
            <div className="card-head"><span className="card-title">Drives</span></div>
            {volumes.length === 0 ? (
              <div className="empty">
                <span className="glyph">💽</span>
                No folders are mounted into the container.<br />
                <span className="hint">
                  Mount each folder under <span className="mono">volumes:</span> in
                  docker-compose.yml at the same path (e.g. <span className="mono">/mnt/files</span>),
                  list it in <span className="mono">VOLUMES</span> in .env, then restart.
                </span>
              </div>
            ) : (
              <div className="grid">
                {volumes.map((v) => {
                  const percent = v.total ? ((v.used ?? 0) / v.total) * 100 : 0
                  return (
                    <button key={v.name} className="card" style={{ textAlign: 'left', cursor: 'pointer' }}
                            onClick={() => go(v.path)}>
                      <div className="row">
                        <span style={{ fontSize: 22 }}>💽</span>
                        <strong>{v.name}</strong>
                        <span className="spacer" />
                        {v.has_shares && <span className="badge accent">shared</span>}
                        {!v.writable && <span className="badge warn">read-only</span>}
                        {v.no_unix_perms && <span className="badge" title="No unix permissions: SMB access is enforced per share only">{v.fs_type}</span>}
                      </div>
                      <div className={`bar ${percent > 92 ? 'danger' : percent > 80 ? 'warn' : ''}`}>
                        <span style={{ width: `${percent}%` }} />
                      </div>
                      <div className="metric-sub">
                        {bytes(v.free)} free of {bytes(v.total)}
                      </div>
                    </button>
                  )
                })}
              </div>
            )}
          </>
        )}

        {/* ------------------------------------------------ browser */}
        {path && (
          <>
            <div className="browser-bar">
              <div className="crumbs">
                <button className="crumb" onClick={() => go('')}>Drives</button>
                {crumbs.map((part, i) => {
                  const target = '/' + crumbs.slice(0, i + 1).join('/')
                  const isLast = i === crumbs.length - 1
                  return (
                    <span key={target} className="row" style={{ gap: 3 }}>
                      <span className="crumb-sep">/</span>
                      <button className={`crumb ${isLast ? 'current' : ''}`}
                              onClick={() => go(target)}>{part}</button>
                    </span>
                  )
                })}
              </div>

              <span className="spacer" />

              <input className="input" style={{ width: 190 }} placeholder="Search this folder…"
                     value={query} onChange={(e) => setQuery(e.target.value)} />

              <select className="select" style={{ width: 'auto' }} value={sortKey}
                      onChange={(e) => setSortKey(e.target.value as SortKey)}>
                <option value="name">Name</option>
                <option value="modified">Date modified</option>
                <option value="size">Size</option>
                <option value="type">Type</option>
              </select>
              <button className="btn sm" onClick={() => setAscending((a) => !a)}
                      title={ascending ? 'Ascending' : 'Descending'}>
                {ascending ? '↑' : '↓'}
              </button>

              <button className="btn sm" onClick={() => setShowHidden((h) => !h)}
                      title="Toggle hidden files">{showHidden ? '👁️' : '🙈'}</button>
              <button className="btn sm" onClick={() => setNewFolder(true)}>New folder</button>
              <button className="btn sm primary" onClick={() => fileInput.current?.click()}>Upload</button>
              <input ref={fileInput} type="file" multiple hidden
                     onChange={(e) => { void handleFiles(e.target.files); e.target.value = '' }} />
            </div>

            {uploads.length > 0 && (
              <div className="card" style={{ marginBottom: 14 }}>
                <div className="card-head"><span className="card-title">Uploading</span></div>
                <div className="stack">
                  {uploads.map((u) => (
                    <div key={u.id}>
                      <div className="row">
                        <span className="truncate" style={{ fontSize: 13 }}>{u.name}</span>
                        <span className="spacer" />
                        <span className="metric-sub">
                          {u.error ? <span style={{ color: 'var(--danger)' }}>{u.error}</span>
                            : `${Math.round(u.progress * 100)}%`}
                        </span>
                      </div>
                      <div className="progress-strip">
                        <span style={{ width: `${u.progress * 100}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selected.size > 0 && (
              <div className="selection-bar">
                <strong>{selected.size} selected</strong>
                <span className="spacer" />
                <button className="btn sm" onClick={() => { setClipboard({ mode: 'copy', paths: [...selected] }); toast('Ready to paste') }}>Copy</button>
                <button className="btn sm" onClick={() => { setClipboard({ mode: 'cut', paths: [...selected] }); toast('Ready to move') }}>Cut</button>
                {clipboard && <button className="btn sm" onClick={() => void paste()}>Paste here</button>}
                <button className="btn sm danger" onClick={() => setConfirmDelete([...selected])}>Delete</button>
                <button className="btn sm ghost" onClick={() => setSelected(new Set())}>Clear</button>
              </div>
            )}

            {error && <div className="notice danger">{error}</div>}
            {searching && listing?.truncated && (
              <div className="notice warn">Showing the first {listing.entries.length} matches.</div>
            )}

            {loading ? (
              <div className="empty"><span className="spin" /></div>
            ) : entries.length === 0 ? (
              <div className="empty">
                <span className="glyph">{searching ? '🔍' : '📂'}</span>
                {searching ? 'Nothing matched that search.' : 'This folder is empty.'}
              </div>
            ) : view === 'list' ? (
              <div className="file-list">
                {entries.map((entry) => (
                  <FileRow key={entry.path} entry={entry}
                           selected={selected.has(entry.path)}
                           onOpen={() => open(entry)}
                           onSelect={(additive) => toggleSelect(entry.path, additive)}
                           onMenu={(x, y) => setMenu({ x, y, entry })} />
                ))}
              </div>
            ) : (
              <div className="file-grid">
                {entries.map((entry) => (
                  <FileTile key={entry.path} entry={entry}
                            selected={selected.has(entry.path)}
                            onOpen={() => open(entry)}
                            onSelect={(additive) => toggleSelect(entry.path, additive)}
                            onMenu={(x, y) => setMenu({ x, y, entry })} />
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {/* ------------------------------------------------ overlays */}

      {menu && (
        <ContextMenu x={menu.x} y={menu.y} items={menuItems(menu.entry)}
                     onClose={() => setMenu(null)} />
      )}

      {newFolder && (
        <NamePrompt title="New folder" label="Folder name" initial="New folder"
                    confirmLabel="Create"
                    onClose={() => setNewFolder(false)}
                    onSubmit={async (name) => {
                      try { await api.mkdir(path, name); toast('Folder created', 'ok'); void load() }
                      catch (e) { toast(e instanceof Error ? e.message : 'Could not create folder', 'error') }
                      setNewFolder(false)
                    }} />
      )}

      {renaming && (
        <NamePrompt title="Rename" label="New name" initial={renaming.name}
                    confirmLabel="Rename"
                    onClose={() => setRenaming(null)}
                    onSubmit={async (name) => {
                      try { await api.rename(renaming.path, name); toast('Renamed', 'ok'); void load() }
                      catch (e) { toast(e instanceof Error ? e.message : 'Could not rename', 'error') }
                      setRenaming(null)
                    }} />
      )}

      {sharing && (
        <ShareDialog path={sharing.path} shareId={sharing.shareId}
                     suggestedName={sharing.name.replace(/[^A-Za-z0-9 ._-]+/g, '-').replace(/^[^A-Za-z0-9]+/, '').slice(0, 64)}
                     fsType={listing?.fs_type} noUnixPerms={listing?.no_unix_perms}
                     onClose={() => setSharing(null)}
                     onDone={() => { setSharing(null); void load(); loadVolumes() }} />
      )}

      {confirmDelete && (
        <Modal title={`Delete ${confirmDelete.length} item${confirmDelete.length === 1 ? '' : 's'}?`}
               subtitle="This removes them from the disk. It cannot be undone."
               onClose={() => setConfirmDelete(null)}
               actions={<>
                 <button className="btn" onClick={() => setConfirmDelete(null)}>Cancel</button>
                 <button className="btn danger" onClick={() => { void doDelete(confirmDelete); setConfirmDelete(null) }}>
                   Delete
                 </button>
               </>}>
          <ul className="mono" style={{ margin: 0, paddingLeft: 18, maxHeight: 200, overflow: 'auto' }}>
            {confirmDelete.slice(0, 20).map((p) => <li key={p}>{p}</li>)}
            {confirmDelete.length > 20 && <li>…and {confirmDelete.length - 20} more</li>}
          </ul>
        </Modal>
      )}

    </>
  )
}

// ------------------------------------------------------------------ pieces

function FileRow({ entry, selected, onOpen, onSelect, onMenu }: {
  entry: Entry; selected: boolean
  onOpen: () => void; onSelect: (additive: boolean) => void
  onMenu: (x: number, y: number) => void
}) {
  const press = useLongPress(onMenu)
  return (
    <div className={`file-row ${selected ? 'selected' : ''}`} {...press}
         onClick={(e) => onSelect(e.metaKey || e.ctrlKey || e.shiftKey)}
         onDoubleClick={onOpen}>
      <span style={{ fontSize: 17 }}>{iconFor(entry)}</span>
      <span className="name">
        <button onClick={(e) => { e.stopPropagation(); onOpen() }}>{entry.name}</button>
        {entry.share && <span className="badge accent" title={`Shared as ${entry.share.name}`}>🔗 {entry.share.name}</span>}
        {entry.is_symlink && <span className="badge">link</span>}
      </span>
      <span className="size">{entry.is_dir ? '—' : bytes(entry.size)}</span>
      <span className="date">{fileDate(entry.modified)}</span>
      <button className="btn ghost icon" onClick={(e) => { e.stopPropagation(); onMenu(e.clientX, e.clientY) }}
              aria-label={`Actions for ${entry.name}`}>⋯</button>
    </div>
  )
}

function FileTile({ entry, selected, onOpen, onSelect, onMenu }: {
  entry: Entry; selected: boolean
  onOpen: () => void; onSelect: (additive: boolean) => void
  onMenu: (x: number, y: number) => void
}) {
  const press = useLongPress(onMenu)
  return (
    <div className={`file-tile ${selected ? 'selected' : ''}`} {...press}
         onClick={(e) => onSelect(e.metaKey || e.ctrlKey || e.shiftKey)}
         onDoubleClick={onOpen}>
      <div className="glyph">{iconFor(entry)}</div>
      <div className="label">{entry.name}</div>
      {entry.share && <div className="badge accent" style={{ marginTop: 6 }}>🔗</div>}
    </div>
  )
}

function NamePrompt({ title, label, initial, confirmLabel, onClose, onSubmit }: {
  title: string; label: string; initial: string; confirmLabel: string
  onClose: () => void; onSubmit: (name: string) => void
}) {
  const [value, setValue] = useState(initial)
  return (
    <Modal title={title} onClose={onClose}
           actions={<>
             <button className="btn" onClick={onClose}>Cancel</button>
             <button className="btn primary" disabled={!value.trim()}
                     onClick={() => onSubmit(value.trim())}>{confirmLabel}</button>
           </>}>
      <div className="field">
        <label htmlFor="name-input">{label}</label>
        <input id="name-input" className="input" value={value} autoFocus
               onChange={(e) => setValue(e.target.value)}
               onKeyDown={(e) => { if (e.key === 'Enter' && value.trim()) onSubmit(value.trim()) }} />
      </div>
    </Modal>
  )
}
