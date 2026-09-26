import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import { AlertTriangle, TerminalSquare, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Badge, Button, cn } from '@/components/ui'

// Right-side terminal drawer. The browser talks only to the Nexus backend
// over a WebSocket; the backend holds the credentials and connects to the
// device over SSH (or Telnet when explicitly enabled).
export function TerminalDrawer({ deviceId, deviceName, protocol, onClose }: { deviceId: number; deviceName: string; protocol: 'ssh' | 'telnet'; onClose: () => void }) {
  const host = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState('Connecting…')
  const [state, setState] = useState<'connecting' | 'open' | 'closed' | 'error'>('connecting')
  const [width, setWidth] = useState(() => Math.min(900, Math.round(window.innerWidth * 0.55)))

  useEffect(() => {
    const term = new Terminal({
      fontFamily: 'JetBrains Mono, ui-monospace, Menlo, Consolas, monospace',
      fontSize: 13,
      cursorBlink: true,
      theme: { background: '#0b1220', foreground: '#e2e8f0', cursor: '#5eead4' },
      scrollback: 5000,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(host.current!)
    fit.fit()
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/api/devices/${deviceId}/cli?protocol=${protocol}&cols=${term.cols}&rows=${term.rows}`)
    const send = (m: object) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(m))
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data as string) as { type: string; data?: string; message?: string }
      if (m.type === 'output' && m.data) {
        const bin = atob(m.data)
        const bytes = new Uint8Array(bin.length)
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
        term.write(bytes)
      } else if (m.type === 'status') {
        setStatus(m.message ?? '')
        if (m.message === 'connected') setState('open')
      } else if (m.type === 'error') {
        setState('error')
        setStatus(m.message ?? 'error')
        term.write(`\r\n\x1b[31m${m.message}\x1b[0m\r\n`)
      } else if (m.type === 'closed') {
        setState('closed')
        setStatus(m.message ?? 'closed')
        term.write(`\r\n\x1b[33m[session closed: ${m.message}]\x1b[0m\r\n`)
      }
    }
    ws.onclose = (e) => {
      setState((s) => (s === 'connecting' ? 'error' : s === 'open' ? 'closed' : s))
      if (e.code !== 1000) setStatus((s) => (s === 'Connecting…' ? 'Could not open the session (check SSH credentials / permissions)' : s))
    }
    const dataSub = term.onData((d) => send({ type: 'input', data: d }))
    const ro = new ResizeObserver(() => {
      try {
        fit.fit()
        send({ type: 'resize', cols: term.cols, rows: term.rows })
      } catch {
        /* element detached */
      }
    })
    ro.observe(host.current!)
    term.focus()
    return () => {
      dataSub.dispose()
      ro.disconnect()
      ws.close()
      term.dispose()
    }
  }, [deviceId, protocol])

  const startDrag = (e: React.MouseEvent) => {
    const startX = e.clientX
    const startW = width
    const move = (ev: MouseEvent) => setWidth(Math.max(420, Math.min(window.innerWidth - 80, startW + startX - ev.clientX)))
    const up = () => {
      window.removeEventListener('mousemove', move)
      window.removeEventListener('mouseup', up)
    }
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
  }

  return (
    <div className="fixed inset-y-0 right-0 z-40 flex animate-slide-in shadow-2xl" style={{ width }}>
      <div className="w-1.5 cursor-col-resize bg-slate-700 hover:bg-brand-500" onMouseDown={startDrag} title="Drag to resize" />
      <div className="flex min-w-0 flex-1 flex-col bg-[#0b1220]">
        <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-2.5 text-sm text-slate-200">
          <TerminalSquare className="size-4 text-brand-400" />
          <span className="font-medium">{deviceName}</span>
          <Badge tone={protocol === 'telnet' ? 'amber' : 'slate'}>{protocol.toUpperCase()}</Badge>
          <span className={cn('ml-2 truncate text-xs', state === 'error' ? 'text-red-400' : state === 'open' ? 'text-emerald-400' : 'text-slate-400')}>{status}</span>
          <div className="flex-1" />
          <Button size="sm" variant="ghost" className="text-slate-300 hover:bg-slate-800" onClick={onClose}>
            <X className="size-4" />
          </Button>
        </div>
        {protocol === 'telnet' && (
          <div className="flex items-center gap-2 bg-amber-900/40 px-4 py-1.5 text-xs text-amber-200">
            <AlertTriangle className="size-3.5" /> Telnet is unencrypted: passwords and commands travel in clear text between Nexus and the device.
          </div>
        )}
        <div ref={host} className="min-h-0 flex-1" />
        <div className="border-t border-slate-800 px-4 py-1.5 text-[11px] text-slate-500">Session is recorded for audit. Idle sessions close automatically.</div>
      </div>
    </div>
  )
}
