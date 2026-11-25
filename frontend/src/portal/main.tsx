import React from 'react'
import { createRoot } from 'react-dom/client'
import { Portal } from './Portal'
import '../styles.css'
import './portal.css'

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Portal />
  </React.StrictMode>,
)
