/** The files portal API. Identity comes from the sign-in proxy, so there is no login here;
 *  every change carries a custom header (a cross-site page can't send one). */

export class PortalError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export interface PortalShare { name: string; access: 'ro' | 'rw' }
export interface Me { user: string; email: string; max_upload_bytes: number; shares: PortalShare[] }
export interface PortalEntry { name: string; is_dir: boolean; size: number | null; modified: number }
export interface Listing { path: string; share: string; access: 'ro' | 'rw'; entries: PortalEntry[] }

const CHANGE = { 'X-SSM-Portal': '1' }

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin', ...init })
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (typeof body?.detail === 'string') detail = body.detail
    } catch { /* not JSON */ }
    throw new PortalError(res.status, detail)
  }
  return res.json() as Promise<T>
}

const post = <T,>(path: string, body: unknown) => call<T>(path, {
  method: 'POST', headers: { ...CHANGE, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
})
const q = encodeURIComponent

export const portal = {
  me: () => call<Me>('/api/portal/me'),
  list: (path: string) => call<Listing>(`/api/portal/list?path=${q(path)}`),
  mkdir: (path: string, name: string) => post<{ name: string }>('/api/portal/mkdir', { path, name }),
  rename: (path: string, name: string) => post<{ name: string }>('/api/portal/rename', { path, name }),
  remove: (path: string) => post<{ deleted: string }>('/api/portal/delete', { path }),
  downloadUrl: (path: string) => `/api/portal/download?path=${q(path)}`,

  /** Upload with progress (fetch can't report upload progress). */
  upload(dir: string, file: File, onProgress: (fraction: number) => void): Promise<{ name: string }> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      xhr.open('PUT', `/api/portal/upload?path=${q(dir)}&name=${q(file.name)}`)
      xhr.setRequestHeader('X-SSM-Portal', '1')
      xhr.setRequestHeader('Content-Type', 'application/octet-stream')
      xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total) }
      xhr.onload = () => {
        let detail = `${xhr.status} ${xhr.statusText}`
        try { detail = JSON.parse(xhr.responseText).detail ?? detail } catch { /* keep */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText))
        else reject(new PortalError(xhr.status, xhr.status === 413 && !detail.includes('limit')
          ? 'File is too large for this connection.' : detail))
      }
      xhr.onerror = () => reject(new PortalError(0, 'Connection lost during upload.'))
      xhr.send(file)
    })
  },
}
