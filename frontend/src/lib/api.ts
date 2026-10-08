/** Typed wrapper around the smb-share-manager API. */

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

// CSRF token for the current session (or the pre-login token). Every state-changing
// request sends it in a header, which a cross-site page cannot do.
let csrfToken = ''

function headersFor(init?: RequestInit): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  const method = (init?.method ?? 'GET').toUpperCase()
  if (method !== 'GET' && method !== 'HEAD') h['X-CSRF-Token'] = csrfToken
  return h
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin', headers: headersFor(init), ...init })

  if (res.status === 401 && !path.startsWith('/api/auth/')) {
    // A dead session lands on the login screen instead of a half-broken page.
    window.dispatchEvent(new CustomEvent('ssm:unauthenticated'))
    throw new ApiError(401, 'Not signed in')
  }

  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body?.detail) detail = typeof body.detail === 'string'
        ? body.detail
        : JSON.stringify(body.detail)
    } catch { /* body was not JSON; keep the status text */ }
    throw new ApiError(res.status, detail)
  }

  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

const get = <T,>(p: string) => request<T>(p)
const post = <T,>(p: string, body?: unknown) =>
  request<T>(p, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
const patch = <T,>(p: string, body: unknown) =>
  request<T>(p, { method: 'PATCH', body: JSON.stringify(body) })
const del = <T,>(p: string) => request<T>(p, { method: 'DELETE' })
const q = encodeURIComponent

// ---------------------------------------------------------------- types

export type Access = 'ro' | 'rw'

export interface Volume {
  name: string; path: string
  total: number | null; used: number | null; free: number | null
  writable: boolean; has_shares?: boolean
  fs_type: string; no_unix_perms: boolean
}

export interface Entry {
  name: string; path: string; type: string; is_dir: boolean
  is_symlink: boolean; size: number | null; modified: number
  hidden: boolean
  share?: { id: string; name: string }
}

export interface Listing {
  path: string; volume: string; writable: boolean; entries: Entry[]
  fs_type: string; no_unix_perms: boolean
  truncated?: boolean; query?: string
}

export interface ShareMember { username: string; access: Access }

export interface Share {
  id: string; name: string; path: string; real_path: string
  members: ShareMember[]; all_users: Access | null
  comment: string; created_at: number | null
  fs_type: string; no_unix_perms: boolean
}

export interface SambaStatus {
  running: boolean; detail: string
  registry_shares: string[]; active_shares: string[]
  missing_shares: string[]; extra_shares: string[]
  missing_users: string[]; extra_users: string[]
}

export interface PermissionPlan {
  path: string; applicable: boolean; changes: string[]
  before: { uid: number; gid: number; mode: string }
}

export interface User {
  username: string; display_name: string; created_at: number | null
  shares?: Array<{ id: string; name: string; access: string | null }>
}

export interface Info {
  version: string; build_date: string; server_name: string; import_mounted: boolean
}

export interface ImportedShare {
  name: string; path: string; local_path: string; comment: string
  members: ShareMember[]; all_users: Access | null
  was_anonymous: boolean; notes: string[]; problems: string[]; exists: boolean
}

export interface ImportScan {
  mounted: boolean; users_error: string
  users: Array<{ username: string; exists: boolean }>
  shares: ImportedShare[]
}

// ---------------------------------------------------------------- endpoints

export const api = {
  authStatus: async () => {
    const s = await get<{ authenticated: boolean; configured: boolean; csrf: string }>('/api/auth/status')
    csrfToken = s.csrf
    return s
  },
  login: async (password: string) => {
    if (!csrfToken) await api.authStatus()
    const r = await post<{ authenticated: boolean; csrf: string }>('/api/auth/login', { password })
    csrfToken = r.csrf
    return r
  },
  logout: () => post<{ authenticated: boolean }>('/api/auth/logout'),
  info: () => get<Info>('/api/info'),

  volumes: () => get<{ volumes: Volume[] }>('/api/files/volumes'),
  list: (path: string, showHidden = false) =>
    get<Listing>(`/api/files/list?path=${q(path)}&show_hidden=${showHidden}`),
  search: (path: string, text: string, showHidden = false) =>
    get<Listing>(`/api/files/search?path=${q(path)}&q=${q(text)}&show_hidden=${showHidden}`),
  mkdir: (parent: string, name: string) => post<Entry>('/api/files/mkdir', { parent, name }),
  rename: (path: string, new_name: string) => post<Entry>('/api/files/rename', { path, new_name }),
  copy: (sources: string[], destination: string) =>
    post<{ copied: string[]; failed: Array<{ source: string; error: string }> }>('/api/files/copy', { sources, destination }),
  move: (sources: string[], destination: string) =>
    post<{ moved: string[]; failed: Array<{ source: string; error: string }> }>('/api/files/move', { sources, destination }),
  remove: (paths: string[]) =>
    post<{ deleted: string[]; failed: Array<{ path: string; error: string }> }>('/api/files/delete', { paths }),
  /** Always a download (Content-Disposition: attachment); files are never shown in the page. */
  downloadUrl: (path: string) => `/api/files/download?path=${q(path)}`,

  shares: () => get<{ shares: Share[]; status: SambaStatus }>('/api/shares'),
  createShare: (body: {
    path: string; name: string; members: ShareMember[]; all_users: Access | null; comment: string
  }) => post<Share>('/api/shares', body),
  updateShare: (id: string, body: Partial<{ members: ShareMember[]; all_users: Access | null; comment: string }>) =>
    patch<Share>(`/api/shares/${q(id)}`, body),
  deleteShare: (id: string) => del<{ removed: string; path: string }>(`/api/shares/${q(id)}`),
  shareConfig: () => get<{ path: string; content: string }>('/api/shares/config'),
  reapply: () => post<{ ok: boolean }>('/api/shares/reapply'),
  permissionPlan: (id: string) => get<PermissionPlan>(`/api/shares/${q(id)}/permissions`),
  applyPermissions: (id: string, before: PermissionPlan['before']) =>
    post<{ changed: boolean }>(`/api/shares/${q(id)}/permissions`, { fix_permissions: true, before }),

  users: () => get<{ users: User[] }>('/api/users'),
  createUser: (body: { username: string; password: string; display_name: string }) =>
    post<User>('/api/users', body),
  updateUser: (username: string, body: { password?: string; display_name?: string }) =>
    patch<User>(`/api/users/${q(username)}`, body),
  deleteUser: (username: string) =>
    del<{ deleted: string; removed_from_shares: string[] }>(`/api/users/${q(username)}`),

  importScan: () => get<ImportScan>('/api/import'),
  importUser: (username: string) => post<{ imported: string }>('/api/import/user', { username }),
  importShare: (name: string, path: string | null, ack_anonymous: boolean) =>
    post<Share>('/api/import/share', { name, path, ack_anonymous }),
}

/** Upload with real progress (fetch() cannot report it). The file is streamed as the
 * raw request body; the server writes it to a temp file and never overwrites. */
export function uploadFile(
  path: string, file: File,
  onProgress: (fraction: number) => void,
  signal?: AbortSignal,
): Promise<{ name: string; path: string; size: number }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('PUT', `/api/files/upload?path=${q(path)}&name=${q(file.name)}`)
    xhr.withCredentials = true
    xhr.setRequestHeader('X-CSRF-Token', csrfToken)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total)
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try { resolve(JSON.parse(xhr.responseText)) }
        catch { reject(new ApiError(xhr.status, 'malformed server response')) }
      } else {
        let detail = `${xhr.status}`
        try { detail = JSON.parse(xhr.responseText).detail ?? detail } catch { /* not JSON */ }
        reject(new ApiError(xhr.status, detail))
      }
    }
    xhr.onerror = () => reject(new ApiError(0, 'network error during upload'))
    xhr.onabort = () => reject(new ApiError(0, 'upload cancelled'))
    signal?.addEventListener('abort', () => xhr.abort())

    xhr.send(file)
  })
}
