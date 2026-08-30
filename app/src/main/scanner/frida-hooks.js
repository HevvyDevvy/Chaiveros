import frida from 'frida'

/**
 * FridaScanner
 *
 * Uses Frida's Node.js bindings to hook encryption library calls
 * across all running processes. Intercepts key material at the
 * point of generation — before it can be exfiltrated by ransomware.
 *
 * Hooked targets:
 *   - Python cryptography.fernet.Fernet.generate_key
 *   - OpenSSL EVP_EncryptInit_ex (AES key setup)
 *   - Windows BCryptGenerateSymmetricKey
 *   - macOS CCCryptorCreate
 */
export class FridaScanner {
  constructor(onEvent) {
    this.onEvent   = onEvent
    this._sessions = []   // active Frida sessions per process
    this._running  = false
    this._deviceMgr = null
  }

  // ── Frida injection script (runs inside target processes) ────────────
  static _SCRIPT = `
    'use strict';

    const emitKey = (source, keyHex, algorithm) => {
      send({
        type: 'KEY_INTERCEPTED',
        severity: 'ALERT',
        data: { source, keyHex, algorithm, pid: Process.id }
      });
    };

    // ── Python: cryptography.fernet ──────────────────────────────────
    try {
      const pyLib = Process.findModuleByName('_cryptography.cpython*.so') ||
                    Process.findModuleByName('_cryptography.pyd');
      if (pyLib) {
        // Hook Fernet.generate_key at the C level
        const sym = pyLib.findExportByName('EVP_CIPHER_CTX_new');
        if (sym) {
          Interceptor.attach(sym, {
            onEnter: function(args) {
              emitKey('fernet', '<ctx_new>', 'Fernet');
            }
          });
        }
      }
    } catch(_) {}

    // ── OpenSSL: EVP_EncryptInit_ex ──────────────────────────────────
    try {
      const ssl = Process.findModuleByName('libssl.so.3') ||
                  Process.findModuleByName('libssl.3.dylib') ||
                  Process.findModuleByName('libssl-3.dll') ||
                  Process.findModuleByName('libcrypto.so.3') ||
                  Process.findModuleByName('libcrypto-3.dll');
      if (ssl) {
        const init = ssl.findExportByName('EVP_EncryptInit_ex');
        if (init) {
          Interceptor.attach(init, {
            onEnter: function(args) {
              // args[2] = const EVP_CIPHER* type (cipher algo)
              // args[3] = const unsigned char* key
              const keyPtr = args[3];
              if (!keyPtr.isNull()) {
                try {
                  const keyBytes = keyPtr.readByteArray(32); // 256-bit
                  const keyHex = Array.from(new Uint8Array(keyBytes))
                    .map(b => b.toString(16).padStart(2,'0')).join('');
                  emitKey('openssl:EVP_EncryptInit_ex', keyHex, 'AES-256');
                } catch(_) {}
              }
            }
          });
        }
      }
    } catch(_) {}

    // ── Windows: BCryptGenerateSymmetricKey ──────────────────────────
    if (Process.platform === 'windows') {
      try {
        const bcrypt = Module.load('bcrypt.dll');
        const genKey = bcrypt.findExportByName('BCryptGenerateSymmetricKey');
        if (genKey) {
          Interceptor.attach(genKey, {
            onEnter: function(args) {
              // args[2] = pbKeyObject, args[3] = cbKeyObject
              // args[4] = pbSecret (key material), args[5] = cbSecret
              const keyPtr  = args[4];
              const keySize = args[5].toInt32();
              if (!keyPtr.isNull() && keySize > 0) {
                try {
                  const keyBytes = keyPtr.readByteArray(keySize);
                  const keyHex = Array.from(new Uint8Array(keyBytes))
                    .map(b => b.toString(16).padStart(2,'0')).join('');
                  emitKey('bcrypt:BCryptGenerateSymmetricKey', keyHex, 'Windows BCrypt');
                } catch(_) {}
              }
            }
          });
        }
      } catch(_) {}
    }

    // ── macOS / iOS: CommonCrypto CCCryptorCreate ────────────────────
    if (Process.platform === 'darwin') {
      try {
        const cc = Module.load('libSystem.B.dylib');
        const create = cc.findExportByName('CCCryptorCreate');
        if (create) {
          Interceptor.attach(create, {
            onEnter: function(args) {
              // args[0]=op, args[1]=alg, args[2]=opts
              // args[3]=key, args[4]=keyLength
              const keyPtr    = args[3];
              const keyLength = args[4].toInt32();
              if (!keyPtr.isNull() && keyLength > 0) {
                try {
                  const keyBytes = keyPtr.readByteArray(keyLength);
                  const keyHex = Array.from(new Uint8Array(keyBytes))
                    .map(b => b.toString(16).padStart(2,'0')).join('');
                  emitKey('commoncrypto:CCCryptorCreate', keyHex, 'CommonCrypto');
                } catch(_) {}
              }
            }
          });
        }
      } catch(_) {}
    }

    recv('stop', () => {});
  `

  // ── Public API ───────────────────────────────────────────────────────

  async start() {
    if (this._running) return
    this._deviceMgr = frida.getDeviceManager()
    const device = await frida.getLocalDevice()
    const processes = await device.enumerateProcesses()

    // Attach to processes that look like potential ransomware targets
    // (skip system processes and ourselves)
    const targets = processes.filter(p =>
      p.pid !== process.pid && !_isSystemProcess(p.name)
    )

    for (const proc of targets) {
      this._attachToProcess(device, proc.pid, proc.name).catch(() => {
        // Silently skip processes we can't attach to (expected for protected procs)
      })
    }

    this._running = true
    this.onEvent({
      type: 'SYSTEM',
      severity: 'INFO',
      data: { message: `Frida hooks active — watching ${targets.length} processes` }
    })
  }

  async _attachToProcess(device, pid, name) {
    const session = await device.attach(pid)
    const script = await session.createScript(FridaScanner._SCRIPT)

    script.message.connect((message) => {
      if (message.type === 'send' && message.payload) {
        this.onEvent({
          ...message.payload,
          data: { ...message.payload.data, processName: name }
        })
      }
    })

    await script.load()
    session.detached.connect(() => {
      this._sessions = this._sessions.filter(s => s.pid !== pid)
    })

    this._sessions.push({ session, script, pid, name })
  }

  async stop() {
    this._running = false
    for (const { session } of this._sessions) {
      await session.detach().catch(() => {})
    }
    this._sessions = []
  }

  isRunning() { return this._running }
}

// Processes to skip attaching to (system critical, would crash or be pointless)
function _isSystemProcess(name) {
  const skip = [
    'kernel', 'kthreadd', 'ksoftirqd', 'systemd', 'launchd',
    'svchost', 'csrss', 'smss', 'lsass', 'winlogon',
    'electron', 'node', 'Electron'
  ]
  return skip.some(s => name.toLowerCase().includes(s.toLowerCase()))
}
