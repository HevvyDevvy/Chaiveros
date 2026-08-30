import { ipcMain, dialog, app } from 'electron'

/**
 * Register all IPC handlers.
 * Called once during app startup with the shared singletons.
 */
export function registerIpcHandlers({ scanner, secureLog, store }) {

  // ── Scanner ────────────────────────────────────────────────────────────

  ipcMain.on('scanner:start', async () => {
    try {
      await scanner.startAll()
    } catch (err) {
      console.error('[IPC] scanner:start failed:', err)
    }
  })

  ipcMain.on('scanner:stop', async () => {
    await scanner.stopAll()
  })

  ipcMain.handle('scanner:status', () => scanner.getStatus())

  ipcMain.handle('scanner:privileges', () => scanner.getPrivileges())

  // ── Settings ───────────────────────────────────────────────────────────

  ipcMain.handle('settings:get', () => store.store)

  ipcMain.on('settings:set', (_event, { key, value }) => {
    store.set(key, value)
    // Live-apply certain settings without restart
    if (key === 'alertThreshold') scanner.setAlertThreshold(value)
    if (key === 'networkInterface') scanner.setInterface(value)
  })

  // ── Secure log ─────────────────────────────────────────────────────────

  ipcMain.on('log:setPath', (_event, path) => {
    store.set('logPath', path)
    secureLog.setPath(path)
  })

  ipcMain.on('log:setPassphrase', (_event, passphrase) => {
    secureLog.unlock(passphrase)
  })

  ipcMain.handle('log:isUnlocked', () => secureLog.isUnlocked())

  ipcMain.handle('log:getPath', () => secureLog.getPath())

  ipcMain.handle('log:read', async (_event, opts = {}) => {
    if (!secureLog.isUnlocked()) return { error: 'LOG_LOCKED' }
    return secureLog.read(opts)
  })

  ipcMain.handle('log:export', async (_event, destPath) => {
    if (!secureLog.isUnlocked()) return { error: 'LOG_LOCKED' }
    return secureLog.exportDecrypted(destPath)
  })

  ipcMain.on('log:clear', () => {
    secureLog.clear()
  })

  // ── Dialogs ────────────────────────────────────────────────────────────

  ipcMain.handle('dialog:openFile', async (_event, opts = {}) => {
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      ...opts
    })
    return result.canceled ? null : result.filePaths[0]
  })

  ipcMain.handle('dialog:saveFile', async (_event, opts = {}) => {
    const result = await dialog.showSaveDialog(opts)
    return result.canceled ? null : result.filePath
  })

  // ── App ────────────────────────────────────────────────────────────────

  ipcMain.handle('app:version', () => app.getVersion())
}
