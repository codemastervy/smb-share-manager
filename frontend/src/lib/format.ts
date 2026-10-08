/** Human-readable formatting helpers. */

export function bytes(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined) return '—'
  if (value === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const exp = Math.min(Math.floor(Math.log(Math.abs(value)) / Math.log(1024)), units.length - 1)
  const scaled = value / Math.pow(1024, exp)
  return `${scaled.toFixed(exp === 0 ? 0 : digits)} ${units[exp]}`
}

export function when(epoch: number | null | undefined): string {
  if (!epoch) return '—'
  const date = new Date(epoch * 1000)
  const elapsed = (Date.now() - date.getTime()) / 1000
  if (elapsed < 60) return 'just now'
  if (elapsed < 3600) return `${Math.floor(elapsed / 60)} min ago`
  if (elapsed < 86400) return `${Math.floor(elapsed / 3600)} h ago`
  if (elapsed < 86400 * 7) return `${Math.floor(elapsed / 86400)} d ago`
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function fileDate(epoch: number): string {
  const date = new Date(epoch * 1000)
  const sameYear = date.getFullYear() === new Date().getFullYear()
  return date.toLocaleDateString(undefined, {
    month: 'short', day: 'numeric',
    year: sameYear ? undefined : 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

/** Pick an icon glyph for a file, from its extension. */
export function iconFor(entry: { is_dir: boolean; name: string }): string {
  if (entry.is_dir) return '📁'
  const ext = entry.name.split('.').pop()?.toLowerCase() ?? ''
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'bmp', 'svg', 'avif'].includes(ext)) return '🖼️'
  if (['mp4', 'mkv', 'mov', 'avi', 'webm', 'm4v'].includes(ext)) return '🎬'
  if (['mp3', 'flac', 'wav', 'aac', 'm4a', 'ogg'].includes(ext)) return '🎵'
  if (['pdf'].includes(ext)) return '📕'
  if (['zip', 'tar', 'gz', 'bz2', 'xz', '7z', 'rar'].includes(ext)) return '🗜️'
  if (['txt', 'md', 'log', 'json', 'yml', 'yaml', 'conf', 'ini', 'csv'].includes(ext)) return '📄'
  if (['iso', 'img', 'dmg'].includes(ext)) return '💿'
  return '📦'
}
