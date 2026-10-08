import { ReactNode, useEffect, useLayoutEffect, useRef, useState } from 'react'

export interface MenuItem {
  label: string
  icon?: string
  danger?: boolean
  separatorBefore?: boolean
  disabled?: boolean
  onSelect: () => void
}

interface Props {
  x: number
  y: number
  items: MenuItem[]
  onClose: () => void
}

export function ContextMenu({ x, y, items, onClose }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState({ x, y })

  useLayoutEffect(() => {
    // Keep the menu on screen when opened near an edge -- particularly on a
    // phone, where a long-press near the bottom is the common case.
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    setPos({
      x: Math.min(x, window.innerWidth - r.width - 8),
      y: Math.min(y, window.innerHeight - r.height - 8),
    })
  }, [x, y])

  useEffect(() => {
    // Capture phase, so this sees the click before anything underneath it
    // does -- but that also means it fires before the menu's OWN buttons get
    // their click, so a click on a menu item must be excluded here rather
    // than relying on stopPropagation() to save it: propagation only
    // affects listeners still pending in the dispatch order, and a capture
    // listener on `document` has already run before the event reaches (and
    // bubbles back out of) a descendant like a menu button.
    const dismissIfOutside = (e: MouseEvent) => {
      if (ref.current?.contains(e.target as Node)) return
      onClose()
    }
    const dismiss = () => onClose()
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('mousedown', dismissIfOutside, true)
    document.addEventListener('scroll', dismiss, true)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', dismissIfOutside, true)
      document.removeEventListener('scroll', dismiss, true)
      document.removeEventListener('keydown', onKey)
    }
  }, [onClose])

  return (
    <div className="context-menu" ref={ref}
         style={{ left: pos.x, top: pos.y }}>
      {items.map((item, i) => (
        <Fragmentish key={i} separator={item.separatorBefore && i > 0}>
          <button className={item.danger ? 'danger' : ''}
                  disabled={item.disabled}
                  onClick={() => { item.onSelect(); onClose() }}>
            <span style={{ width: 16 }}>{item.icon}</span>{item.label}
          </button>
        </Fragmentish>
      ))}
    </div>
  )
}

function Fragmentish({ separator, children }: { separator?: boolean; children: ReactNode }) {
  return <>{separator && <hr />}{children}</>
}

/** Wires up right-click and long-press to the same handler. */
export function useLongPress(onTrigger: (x: number, y: number) => void) {
  const timer = useRef<number>()
  const origin = useRef({ x: 0, y: 0 })

  const cancel = () => { window.clearTimeout(timer.current) }

  return {
    onContextMenu: (e: React.MouseEvent) => {
      e.preventDefault()
      onTrigger(e.clientX, e.clientY)
    },
    onTouchStart: (e: React.TouchEvent) => {
      const t = e.touches[0]
      origin.current = { x: t.clientX, y: t.clientY }
      timer.current = window.setTimeout(() => onTrigger(t.clientX, t.clientY), 480)
    },
    onTouchMove: (e: React.TouchEvent) => {
      const t = e.touches[0]
      // A scroll should not become a long-press.
      if (Math.hypot(t.clientX - origin.current.x, t.clientY - origin.current.y) > 10) cancel()
    },
    onTouchEnd: cancel,
    onTouchCancel: cancel,
  }
}
