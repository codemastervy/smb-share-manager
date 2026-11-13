import { ReactNode } from 'react'

/* One small stroke-icon set, drawn on a 24px grid. Inline SVG so the UI has
   no icon font, no network request, and icons inherit `currentColor`. */

const PATHS: Record<string, ReactNode> = {
  // navigation and chrome
  gauge: <><path d="M4.5 18a9 9 0 1 1 15 0" /><path d="M12 13l4-5" /><circle cx="12" cy="13" r="1.2" /></>,
  folder: <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4.6l2 2.2h8.4A1.5 1.5 0 0 1 21 9.7v8.8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z" />,
  'folder-open': <><path d="M3 18.5v-11A1.5 1.5 0 0 1 4.5 6h4.6l2 2.2h7.4A1.5 1.5 0 0 1 20 9.7V11" /><path d="M3.2 19l2.4-7a1.5 1.5 0 0 1 1.4-1h13.4a1 1 0 0 1 .95 1.3L19.3 19a1.5 1.5 0 0 1-1.4 1H4.5A1.4 1.4 0 0 1 3.2 19z" /></>,
  'folder-plus': <><path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4.6l2 2.2h8.4A1.5 1.5 0 0 1 21 9.7v8.8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z" /><path d="M12 11.5v5M9.5 14h5" /></>,
  share: <><circle cx="6" cy="12" r="2.5" /><circle cx="18" cy="6" r="2.5" /><circle cx="18" cy="18" r="2.5" /><path d="M8.2 10.9l7.6-3.8M8.2 13.1l7.6 3.8" /></>,
  users: <><circle cx="9" cy="8.5" r="3.2" /><path d="M2.8 19.5a6.2 6.2 0 0 1 12.4 0" /><path d="M16 5.6a3.2 3.2 0 0 1 0 5.8M18 14.2a6.2 6.2 0 0 1 3.2 5.3" /></>,
  apps: <><rect x="4" y="4" width="6.5" height="6.5" rx="1.2" /><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.2" /><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.2" /><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.2" /></>,
  import: <><path d="M12 3.5v10M8 9.8l4 4 4-4" /><path d="M3.5 14.5h4.2l1.3 2.5h6l1.3-2.5h4.2v4a1.5 1.5 0 0 1-1.5 1.5H5a1.5 1.5 0 0 1-1.5-1.5z" /></>,
  server: <><rect x="3.5" y="4" width="17" height="6.5" rx="1.5" /><rect x="3.5" y="13.5" width="17" height="6.5" rx="1.5" /><path d="M7 7.25h.01M7 16.75h.01M11 7.25h6M11 16.75h6" /></>,
  drive: <><path d="M5.6 5.2A1.5 1.5 0 0 1 7 4.2h10a1.5 1.5 0 0 1 1.4 1L21 13v5.3a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.3V13z" /><path d="M3 13h18M7 16.4h.01M10.5 16.4h.01" /></>,
  sun: <><circle cx="12" cy="12" r="3.8" /><path d="M12 2.8v2M12 19.2v2M2.8 12h2M19.2 12h2M5.5 5.5l1.4 1.4M17.1 17.1l1.4 1.4M5.5 18.5l1.4-1.4M17.1 6.9l1.4-1.4" /></>,
  moon: <path d="M20 14.2A8.3 8.3 0 0 1 9.8 4a8.3 8.3 0 1 0 10.2 10.2z" />,
  logout: <><path d="M9.5 20H5.5A1.5 1.5 0 0 1 4 18.5v-13A1.5 1.5 0 0 1 5.5 4h4" /><path d="M15.5 16.5L20 12l-4.5-4.5M20 12H9.5" /></>,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  list: <path d="M8.5 6.5H20M8.5 12H20M8.5 17.5H20M4 6.5h.01M4 12h.01M4 17.5h.01" />,
  grid: <><rect x="4" y="4" width="6.5" height="6.5" rx="1" /><rect x="13.5" y="4" width="6.5" height="6.5" rx="1" /><rect x="4" y="13.5" width="6.5" height="6.5" rx="1" /><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1" /></>,
  settings: <><path d="M4 7h9M17 7h3M4 12h3M11 12h9M4 17h11M19 17h1" /><circle cx="15" cy="7" r="2" /><circle cx="9" cy="12" r="2" /><circle cx="17" cy="17" r="2" /></>,
  transfers: <path d="M7.5 20V5M4 8.5L7.5 5 11 8.5M16.5 4v15M13 15.5l3.5 3.5 3.5-3.5" />,
  search: <><circle cx="10.8" cy="10.8" r="6.3" /><path d="M20 20l-4.6-4.6" /></>,
  subfolders: <><path d="M5 4v13.5A1.5 1.5 0 0 0 6.5 19H11M5 9.5h6" /><rect x="13" y="6.5" width="7" height="6" rx="1.2" /><rect x="13" y="16" width="7" height="5" rx="1.2" /></>,
  external: <><path d="M13.5 4.5h6v6M19.5 4.5L11 13" /><path d="M18 14v4.5A1.5 1.5 0 0 1 16.5 20h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10" /></>,

  // file types
  file: <><path d="M13.5 3.5h-7A1.5 1.5 0 0 0 5 5v14a1.5 1.5 0 0 0 1.5 1.5h11A1.5 1.5 0 0 0 19 19V9z" /><path d="M13.5 3.5V9H19" /></>,
  'file-text': <><path d="M13.5 3.5h-7A1.5 1.5 0 0 0 5 5v14a1.5 1.5 0 0 0 1.5 1.5h11A1.5 1.5 0 0 0 19 19V9z" /><path d="M13.5 3.5V9H19M8.5 13h7M8.5 16.5h5" /></>,
  image: <><rect x="3.5" y="4.5" width="17" height="15" rx="1.8" /><circle cx="8.6" cy="9.6" r="1.6" /><path d="M20.5 15.5l-4.6-4.6L6 19.5" /></>,
  video: <><rect x="3.5" y="5" width="17" height="14" rx="1.8" /><path d="M10 9.3v5.4l4.6-2.7z" /></>,
  music: <><path d="M9 17.5V6l10-2v11.5" /><circle cx="6.5" cy="17.5" r="2.5" /><circle cx="16.5" cy="15.5" r="2.5" /></>,
  archive: <><rect x="3.5" y="4" width="17" height="5" rx="1.2" /><path d="M5 9v9.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V9M10 13h4" /></>,
  disc: <><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="2.2" /></>,
  package: <><path d="M12 3.2l8 4.4v8.8l-8 4.4-8-4.4V7.6z" /><path d="M4.3 7.8L12 12l7.7-4.2M12 12v8.6" /></>,

  // actions
  upload: <><path d="M12 15.5V4M7.5 8.5L12 4l4.5 4.5" /><path d="M4.5 15.5v3A1.5 1.5 0 0 0 6 20h12a1.5 1.5 0 0 0 1.5-1.5v-3" /></>,
  download: <><path d="M12 4v11.5M7.5 11L12 15.5 16.5 11" /><path d="M4.5 15.5v3A1.5 1.5 0 0 0 6 20h12a1.5 1.5 0 0 0 1.5-1.5v-3" /></>,
  clipboard: <><rect x="5" y="5" width="14" height="15.5" rx="1.6" /><path d="M9 5V4.2A.7.7 0 0 1 9.7 3.5h4.6a.7.7 0 0 1 .7.7V5a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1z" /></>,
  refresh: <><path d="M20 5v5h-5" /><path d="M19.4 14.5A7.8 7.8 0 1 1 18 7.2L20 10" /></>,
  eye: <><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" /><circle cx="12" cy="12" r="2.8" /></>,
  'eye-off': <><path d="M10 5.7a8.6 8.6 0 0 1 2-.2c6 0 9.500 6.500 9.500 6.500a15 15 0 0 1-2.400 3.200M6.300 7.300A14.600 14.600 0 0 0 2.500 12S6 18.500 12 18.500a8.700 8.700 0 0 0 4.300-1.200" /><path d="M3.500 3.500l17 17M9.900 9.900a2.900 2.900 0 0 0 4.100 4.100" /></>,
  pencil: <><path d="M4 20l1-4.500L15.800 4.700a1.700 1.700 0 0 1 2.400 0l1.100 1.100a1.700 1.700 0 0 1 0 2.400L8.500 19z" /><path d="M14 6.500l3.500 3.500" /></>,
  copy: <><rect x="8.500" y="8.500" width="11.500" height="11.500" rx="1.600" /><path d="M5.500 15.500H5A1.500 1.500 0 0 1 3.500 14V5A1.500 1.500 0 0 1 5 3.500h9A1.500 1.500 0 0 1 15.500 5v.500" /></>,
  scissors: <><circle cx="6" cy="6.500" r="2.500" /><circle cx="6" cy="17.500" r="2.500" /><path d="M8.100 8.100L20 19M8.100 15.900L20 5M12 12h.01" /></>,
  trash: <><path d="M4 6.500h16M9.500 6.500V4.800a.8.800 0 0 1 .8-.8h3.400a.8.800 0 0 1 .8.8v1.700" /><path d="M6 6.500l.9 12.100A1.500 1.500 0 0 0 8.400 20h7.200a1.500 1.500 0 0 0 1.500-1.400L18 6.500M10 10.500v5.500M14 10.500v5.500" /></>,
  play: <path d="M7 4.800v14.400L19 12z" />,
  stop: <rect x="6" y="6" width="12" height="12" rx="1.500" />,
  retry: <><path d="M4 5v5h5" /><path d="M4.600 14.500A7.800 7.800 0 1 0 6 7.200L4 10" /></>,

  // status
  link: <><path d="M10 14a4.200 4.200 0 0 0 6 0l3.200-3.200a4.200 4.200 0 0 0-6-6L12 6" /><path d="M14 10a4.200 4.200 0 0 0-6 0l-3.200 3.200a4.200 4.200 0 0 0 6 6L12 18" /></>,
  wifi: <><path d="M3 9.500a13 13 0 0 1 18 0M6.200 13a8.300 8.300 0 0 1 11.600 0M9.300 16.300a3.900 3.900 0 0 1 5.400 0" /><path d="M12 19.500h.01" /></>,
  ethernet: <><rect x="3.500" y="5" width="17" height="14" rx="1.800" /><path d="M8 19v-4.500h8V19M8.500 9v2M12 9v2M15.500 9v2" /></>,
  warning: <><path d="M12 4.200L21.200 19.500H2.800z" /><path d="M12 10v4.500M12 17h.01" /></>,
  lock: <><rect x="5" y="10.500" width="14" height="9.500" rx="1.800" /><path d="M8.200 10.500V8a3.800 3.800 0 0 1 7.600 0v2.500" /></>,
  key: <><circle cx="8" cy="15" r="4" /><path d="M11 12l8.500-8.500M16 7l2.500 2.500M19.500 3.500l1 1" /></>,
  blocked: <><circle cx="12" cy="12" r="8.500" /><path d="M6 6l12 12" /></>,
  unreachable: <><path d="M12 12.500v8M5.500 19.200a9.200 9.200 0 0 1 0-13.400M18.500 5.800a9.200 9.200 0 0 1 0 13.400M8.400 16.300a5.200 5.200 0 0 1 0-7.600M15.600 8.700a5.200 5.200 0 0 1 0 7.600" /><circle cx="12" cy="12.500" r="1.300" /></>,
  move: <path d="M4 12h15M14.500 7.500L19 12l-4.500 4.500" />,
}

interface Props {
  name: string
  size?: number
  className?: string
}

export function Icon({ name, size = 16, className }: Props) {
  return (
    <svg className={`icon${className ? ` ${className}` : ''}`} data-icon={name}
         width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth={1.7} strokeLinecap="round"
         strokeLinejoin="round" aria-hidden="true" focusable="false">
      {PATHS[name] ?? PATHS.file}
    </svg>
  )
}
