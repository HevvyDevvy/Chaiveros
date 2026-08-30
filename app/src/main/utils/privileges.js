import { platform } from 'os'
import { execSync } from 'child_process'

const OS = platform()

/**
 * Detect what the app can and cannot do on this OS with current privileges.
 * Called once at startup and passed to all scanners.
 */
export async function checkPrivileges() {
  const privs = {
    isElevated:    false,
    canSniff:      false,
    canReadMemory: false,
    canReadProc:   false,
    canLoadKernel: false,
    os:            OS,
    details:       {}
  }

  switch (OS) {
    case 'linux':   return _checkLinux(privs)
    case 'darwin':  return _checkMac(privs)
    case 'win32':   return _checkWindows(privs)
    default:        return privs
  }
}

function _checkLinux(privs) {
  const uid = process.getuid?.() ?? 1000

  privs.isElevated    = uid === 0
  privs.canReadProc   = true   // /proc is always readable for own processes
  privs.canReadMemory = uid === 0

  // Check CAP_NET_RAW (allows packet capture without full root)
  try {
    const caps = execSync('cat /proc/self/status', { stdio: 'pipe' }).toString()
    const capEffLine = caps.match(/CapEff:\s*([0-9a-f]+)/i)
    if (capEffLine) {
      const capEff = BigInt('0x' + capEffLine[1])
      // CAP_NET_RAW = bit 13
      privs.canSniff = !!(capEff & BigInt(1 << 13)) || uid === 0
    }
  } catch {
    privs.canSniff = uid === 0
  }

  privs.canLoadKernel = uid === 0
  privs.details = { uid, hint: uid !== 0 ? 'Run with sudo for full capabilities' : 'Full privileges' }
  return privs
}

function _checkMac(privs) {
  const uid = process.getuid?.() ?? 501

  privs.isElevated    = uid === 0
  privs.canSniff      = uid === 0  // BPF requires root on macOS
  privs.canReadMemory = uid === 0
  privs.canReadProc   = uid === 0

  // Check if SIP is enabled (affects kext loading)
  let sipEnabled = true
  try {
    const out = execSync('csrutil status 2>/dev/null', { stdio: 'pipe' }).toString()
    sipEnabled = !out.includes('disabled')
  } catch {
    sipEnabled = true
  }

  privs.canLoadKernel = uid === 0 && !sipEnabled
  privs.details = {
    uid,
    sipEnabled,
    hint: sipEnabled
      ? 'SIP is enabled — kernel extension cannot load. Disable in Recovery Mode for lab use.'
      : uid !== 0 ? 'SIP disabled but not root — run with sudo' : 'Full privileges'
  }
  return privs
}

function _checkWindows(privs) {
  // Check for admin via `net session` — throws if not admin
  try {
    execSync('net session', { stdio: 'pipe' })
    privs.isElevated    = true
    privs.canSniff      = true   // Npcap needed too
    privs.canReadMemory = true
    privs.canReadProc   = true
    privs.canLoadKernel = true
  } catch {
    privs.isElevated    = false
    privs.details.hint  = 'Run as Administrator for full capabilities'
  }

  // Check for Npcap (required for packet capture)
  try {
    execSync('sc query npcap', { stdio: 'pipe' })
    privs.details.npcap = true
  } catch {
    privs.canSniff        = false
    privs.details.npcap   = false
    privs.details.npcapHint = 'Install Npcap from https://npcap.com for packet capture'
  }

  return privs
}
