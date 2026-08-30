import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  // ── Main process ───────────────────────────
  main: {
    plugins: [externalizeDepsPlugin()],
    build: {
      rollupOptions: {
        // Keep native modules external — electron-rebuild handles them
        external: ['frida', 'cap', 'systeminformation', 'electron-store']
      }
    }
  },

  // ── Preload ────────────────────────────────
  preload: {
    plugins: [externalizeDepsPlugin()]
  },

  // ── Renderer (React + Vite) ────────────────
  renderer: {
    plugins: [react()],
    resolve: {
      alias: {
        '@components': resolve('src/renderer/components'),
        '@styles': resolve('src/renderer/styles')
      }
    },
    build: {
      rollupOptions: {
        input: {
          index: resolve('src/renderer/index.html')
        }
      }
    }
  }
})
