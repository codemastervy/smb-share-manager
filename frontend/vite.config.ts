import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', sourcemap: false, modulePreload: { polyfill: false } },
  server: {
    port: 5173,
    // `npm run dev` talks to a running container (web UI on port 8095).
    proxy: { '/api': { target: 'http://localhost:8095' } },
  },
})
