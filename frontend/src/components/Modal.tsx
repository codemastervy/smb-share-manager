import { ReactNode, useEffect, useRef } from 'react'

interface Props {
  title: string
  subtitle?: string
  onClose: () => void
  children: ReactNode
  actions?: ReactNode
}

export function Modal({ title, subtitle, onClose, children, actions }: Props) {
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    // Focus the first control so the dialog is usable from the keyboard.
    box.current?.querySelector<HTMLElement>('input, select, textarea, button')?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="modal" ref={box} role="dialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>
        {subtitle && <div className="sub">{subtitle}</div>}
        {children}
        {actions && <div className="modal-actions">{actions}</div>}
      </div>
    </div>
  )
}
