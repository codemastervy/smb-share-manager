import { createContext, ReactNode, useCallback, useContext, useState } from 'react'

type Kind = 'info' | 'ok' | 'error'
interface Note { id: number; kind: Kind; text: string }

const ToastContext = createContext<(text: string, kind?: Kind) => void>(() => {})

export const useToast = () => useContext(ToastContext)

export function ToastHost({ children }: { children: ReactNode }) {
  const [notes, setNotes] = useState<Note[]>([])

  const push = useCallback((text: string, kind: Kind = 'info') => {
    const id = Date.now() + Math.random()
    setNotes((n) => [...n, { id, kind, text }])
    // Errors linger; confirmations get out of the way.
    window.setTimeout(() => setNotes((n) => n.filter((x) => x.id !== id)),
      kind === 'error' ? 7000 : 3400)
  }, [])

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div style={{
        position: 'fixed', bottom: 18, right: 18, zIndex: 300,
        display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 'min(380px, calc(100vw - 36px))',
      }}>
        {notes.map((n) => (
          <div key={n.id} className={`notice ${n.kind === 'error' ? 'danger' : n.kind === 'ok' ? 'accent' : ''}`}
               style={{ margin: 0, boxShadow: 'var(--shadow)', background: 'var(--bg-elevated)' }}>
            {n.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
