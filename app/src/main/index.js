import { app, BrowserWindow, Tray, Menu, nativeImage, dialog } from 'electron'
import { join } from 'path'
import { registerIpcHandlers } from './ipc.js'
import { ScannerOrchestrator } from './scanner/index.js'
import { SecureLog } from './logger/secure-log.js'
import Store from 'electron-store'
import { checkPrivileges } from './utils/privileges.js'

// ── App-wide singletons ────────────────────────────────────────────────────
let mainWindow = null
let tray = null
export let scanner = null
export let secureLog = null
export const store = new Store({
  defaults: {
    logPath: app.getPath('userData') + '/defense.rwdlog',
    alertThreshold: 5,
    monitorPackets: true,
    monitorMemory: true,
    monitorLibraries: true,
    monitorKernel: true,
    networkInterface: 'auto',
    windowBounds: { width: 1200, height: 800 }
  }
})

// ── Window ────────────────────────────────────────────────────────────────
function createWindow() {
  const { width, height } = store.get('windowBounds')

  mainWindow = new BrowserWindow({
    width,
    height,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0A0D14',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    frame: process.platform !== 'darwin',
    icon: join(__dirname, '../../resources/icons/icon.png'),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,      // MUST be true — security boundary
      nodeIntegration: false,      // MUST be false
      sandbox: false,              // false needed for preload access to node
      webSecurity: true
    }
  })

  // Save window size on close
  mainWindow.on('resize', () => {
    store.set('windowBounds', mainWindow.getBounds())
  })

  mainWindow.on('close', (e) => {
    if (process.platform === 'darwin') {
      e.preventDefault()
      mainWindow.hide()
    }
  })

  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL('http://localhost:5173')
    mainWindow.webContents.openDevTools()
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }

  return mainWindow
}

// ── System tray ───────────────────────────────────────────────────────────
function createTray() {
  const icon = nativeImage.createFromPath(
    join(__dirname, '../../resources/icons/tray.png')
  )
  tray = new Tray(icon)

  const updateMenu = (scanning) => {
    const menu = Menu.buildFromTemplate([
      { label: 'Ransomware Defense', enabled: false },
      { type: 'separator' },
      {
        label: scanning ? '● Scanning' : '○ Stopped',
        enabled: false,
        icon: nativeImage.createFromDataURL(
          scanning ? greenDot() : redDot()
        )
      },
      { type: 'separator' },
      { label: 'Open', click: () => mainWindow?.show() },
      { type: 'separator' },
      { label: 'Quit', click: () => { app.isQuitting = true; app.quit() } }
    ])
    tray.setContextMenu(menu)
  }

  tray.setToolTip('Ransomware Defense')
  tray.on('double-click', () => mainWindow?.show())
  updateMenu(false)

  return { tray, updateMenu }
}

// ── Startup ───────────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  // Check privilege level — some scanners need root/admin
  const privs = await checkPrivileges()

  // Initialise secure log (passphrase set by user on first run via IPC)
  secureLog = new SecureLog(store.get('logPath'))

  // Initialise scanner orchestrator
  scanner = new ScannerOrchestrator({
    store,
    secureLog,
    privileges: privs,
    onEvent: (event) => {
      mainWindow?.webContents.send('scanner:event', event)
    },
    onAlert: (alert) => {
      mainWindow?.webContents.send('scanner:alert', alert)
    }
  })

  // Register all IPC handlers
  registerIpcHandlers({ scanner, secureLog, store })

  // Create UI
  const win = createWindow()
  const { updateMenu } = createTray()

  // Reflect scanning state in tray
  scanner.on('started', () => updateMenu(true))
  scanner.on('stopped', () => updateMenu(false))

  // Send privilege info to renderer once ready
  win.webContents.once('did-finish-load', () => {
    win.webContents.send('app:privileges', privs)
    win.webContents.send('app:logPath', store.get('logPath'))
  })

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
    else mainWindow?.show()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', async () => {
  await scanner?.stopAll()
  await secureLog?.flush()
})

// Tiny inline dot icons for tray menu
function greenDot() {
  return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAP0lEQVQoU2NkYGD4z8DAwMgABf8ZGBj+MzAwMKALMKILMDIyMqILMDIyMqILMDAwMKALMDIyMqILMDAwMKAL0AMAAD4BLgFY5EEAAAAASUVORK5CYII='
}
function redDot() {
  return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAP0lEQVQoU2P8z8Dwn4GBgREK/jMwMPxnYGBgQBdgRBdgZGRkRBdgZGRkRBdgYGBgQBdgZGRkRBdgYGBgQBdgYGAA7AEuAVgRPQAAAABJRU5ErkJggg=='
}
