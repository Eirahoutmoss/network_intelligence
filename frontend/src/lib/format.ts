export function bps(v: number | null | undefined): string {
  if (v === null || v === undefined || isNaN(v)) return '—'
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']
  let i = 0
  let n = v
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000
    i++
  }
  return `${n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${units[i]}`
}

export function speed(v: number | null | undefined): string {
  if (!v) return '—'
  if (v >= 1e9) return `${+(v / 1e9).toFixed(1)}G`
  if (v >= 1e6) return `${+(v / 1e6).toFixed(0)}M`
  return `${v}`
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return '—'
  const s = (Date.now() - new Date(iso).getTime()) / 1000
  if (s < 0) return 'just now'
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export function uptime(sec: number | null | undefined): string {
  if (!sec) return '—'
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  return d > 0 ? `${d}d ${h}h` : `${h}h ${m}m`
}

export function pct(v: number | null | undefined): string {
  if (v === null || v === undefined) return '—'
  return `${Math.round(v * 100)}%`
}

export const TYPE_LABELS: Record<string, string> = {
  router: 'Router',
  switch: 'Switch',
  firewall: 'Firewall',
  access_point: 'Access point',
  wireless_controller: 'Wireless controller',
  printer: 'Printer',
  computer: 'Computer',
  server: 'Server',
  phone: 'IP phone',
  camera: 'Camera',
  storage: 'Storage',
  ups: 'UPS',
  iot: 'IoT device',
  virtual_machine: 'Virtual machine',
  mobile: 'Mobile device',
  unknown: 'Unknown',
}

export const DEVICE_TYPES = Object.keys(TYPE_LABELS)

export function typeLabel(t: string | null | undefined): string {
  return TYPE_LABELS[t ?? 'unknown'] ?? t ?? 'Unknown'
}

export const SOURCE_LABELS: Record<string, string> = {
  seed: 'Added by you',
  lldp: 'LLDP neighbor',
  cdp: 'CDP neighbor',
  arp: 'ARP table',
  fdb: 'MAC table',
  refresh: 'Refresh',
  poll: 'Polling',
}
