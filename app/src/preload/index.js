/**
 * preload/index.js
 *
 * This is the ONLY bridge between the sandboxed renderer and Node/Electron.
 * Every API exposed here is deliberate and minimal.
 * contextIsolation: true means the renderer cannot access `require` or Node APIs directly.
 */
import { contextBridge, ipcRenderer } from 'electron'

// ── Whitelist of valid IPC channels ──────────────────────────────────────
const VALID_SEND = new Set([
  'scanner:start',
  'scanner:stop',
  'settings:set',
  'log:setPath',
  'log:setPassphrase',
  'log:read',
  'log:export',
  'log:clear'
])

const VALID_INVOKE = new Set([
  'scanner:status',
  'scanner:privileges',
  'settings:get',
  'log:getPath',
  'log:isUnlocked',
  'log:read',
  'log:export',
  'dialog:openFile',
  'dialog:saveFile',
  'app:version',
  'recovery:preview',
  'recovery:run',
  'recovery:undo'
])

const VALID_ON = new Set([
  'scanner:event',
  'scanner:alert',
  'scanner:status-change',
  'app:privileges',
  'app:logPath',
  'log:entry'
])

// ── Exposed API (available as window.rwd in renderer) ────────────────────
contextBridge.exposeInMainWorld('rwd', {
  // Scanner control
  scanner: {
    start: ()           => ipcRenderer.send('scanner:start'),
    stop:  ()           => ipcRenderer.send('scanner:stop'),
    status: ()          => ipcRenderer.invoke('scanner:status'),
    privileges: ()      => ipcRenderer.invoke('scanner:privileges')
  },

  // Settings
  settings: {
    get: ()             => ipcRenderer.invoke('settings:get'),
    set: (key, value)   => ipcRenderer.send('settings:set', { key, value })
  },

  // Secure log
  log: {
    setPath: (path)        => ipcRenderer.send('log:setPath', path),
    setPassphrase: (pp)    => ipcRenderer.send('log:setPassphrase', pp),
    isUnlocked: ()         => ipcRenderer.invoke('log:isUnlocked'),
    read: (opts)           => ipcRenderer.invoke('log:read', opts),
    export: (destPath)     => ipcRenderer.invoke('log:export', destPath),
    clear: ()              => ipcRenderer.send('log:clear'),
    getPath: ()            => ipcRenderer.invoke('log:getPath')
  },

  // Recovery (Rescue) — file / directory / full-system decryption
  recovery: {
    preview: (scope, target, opts) => ipcRenderer.invoke('recovery:preview', { scope, target, opts }),
    run:     (scope, target, keyHex, algorithm, opts) =>
      ipcRenderer.invoke('recovery:run', { scope, target, keyHex, algorithm, opts }),
    undo:    () => ipcRenderer.invoke('recovery:undo')
  },

  // Dialogs
  dialog: {
    openFile:  (opts) => ipcRenderer.invoke('dialog:openFile', opts),
    saveFile:  (opts) => ipcRenderer.invoke('dialog:saveFile', opts)
  },

  // App info
  app: {
    version: () => ipcRenderer.invoke('app:version')
  },

  // Event subscriptions (renderer → listen for main process push events)
  on: (channel, callback) => {
    if (!VALID_ON.has(channel)) {
      console.warn(`[preload] Blocked subscription to unknown channel: ${channel}`)
      return () => {}
    }
    const wrapped = (_event, ...args) => callback(...args)
    ipcRenderer.on(channel, wrapped)
    // Returns an unsubscribe function
    return () => ipcRenderer.removeListener(channel, wrapped)
  }
})
