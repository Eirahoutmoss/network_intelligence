import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ArrowRight, Network, RefreshCw, Sparkles } from 'lucide-react'
import { api } from '@/api/client'
import type { NetEvent } from '@/api/types'
import { DeviceIcon, TYPE_COLORS } from '@/components/DeviceIcon'
import { Badge, Button, Card, Empty, Loading, PageHeader, Stat } from '@/components/ui'
import { ago, bps, typeLabel } from '@/lib/format'
import { useAuth } from '@/lib/auth'
import { useState } from 'react'

interface Dash {
  totals: Record<string, number>
  by_type: { type: string; count: number }[]
  by_vendor: { vendor: string; count: number }[]
  by_os: { os: string; count: number }[]
  recent_events: NetEvent[]
  recent_runs: { id: number; seed_ip: string; status: string; summary: Record<string, any>; created_at: string }[]
  top_ports: { id: number; device_id: number; device: string; port: string; bps: number; utilization: number | null }[]
}

export function Bars({ rows, color }: { rows: { label: React.ReactNode; value: number; color?: string; to?: string }[]; color?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value))
  return (
    <ul className="space-y-1.5">
      {rows.map((r, i) => (
        <li key={i} className="grid grid-cols-[minmax(0,10rem)_1fr_3rem] items-center gap-2 text-sm">
          <span className="truncate text-slate-600">{r.to ? <Link to={r.to} className="hover:text-brand-700 hover:underline">{r.label}</Link> : r.label}</span>
          <span className="h-2 rounded-full bg-slate-100">
            <span className="block h-2 rounded-full" style={{ width: `${(r.value / max) * 100}%`, background: r.color ?? color ?? '#0d9488' }} />
          </span>
          <span className="text-right tabular-nums text-slate-700">{r.value}</span>
        </li>
      ))}
    </ul>
  )
}

export const sevTone = (s: string) => (s === 'critical' ? 'red' : s === 'warning' ? 'amber' : 'slate') as 'red' | 'amber' | 'slate'

export default function Dashboard() {
  const { can } = useAuth()
  const [refreshing, setRefreshing] = useState(false)
  const q = useQuery({ queryKey: ['dashboard'], queryFn: () => api.get<Dash>('/api/dashboard'), refetchInterval: 30_000 })
  if (q.isLoading) return <Loading />
  const d = q.data
  if (!d) return null
  const t = d.totals ?? {}
  if (!t.devices) {
    return (
      <div className="p-6">
        <PageHeader title="Welcome to Nexus" subtitle="Give the system access to one network device. It will work out the rest." />
        <Card>
          <Empty icon={<Network className="size-12" />} title="No devices yet">
            Click <b>Add Device</b> in the sidebar and enter the IP address of a switch or router with its SNMP username and password.
            Nexus will discover its neighbors, the devices connected to it, and build the topology automatically.
          </Empty>
        </Card>
      </div>
    )
  }
  return (
    <div className="space-y-5 p-6">
      <PageHeader
        title="Dashboard"
        subtitle="What is on this network right now"
        actions={
          can('operator') && (
            <Button
              loading={refreshing}
              onClick={async () => {
                setRefreshing(true)
                try {
                  await api.post('/api/discovery/refresh')
                } catch {
                  /* already running */
                }
                setTimeout(() => setRefreshing(false), 800)
              }}
            >
              <RefreshCw className="size-4" /> Rediscover
            </Button>
          )
        }
      />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Devices" value={t.devices} hint={`${t.new_24h ?? 0} new in 24h`} />
        <Stat label="Network devices" value={t.managed} hint="polled via SNMP" />
        <Stat label="Endpoints" value={t.endpoints} />
        <Stat label="Links" value={t.links} hint={`${t.subnets} subnets`} />
        <Stat label="Unreachable" value={t.down} tone={t.down ? 'red' : 'green'} />
        <Stat label="Open alerts" value={t.open_alerts} tone={t.open_alerts ? 'amber' : 'green'} />
      </div>
      <Link to="/explore" className="flex items-center gap-3 rounded-xl border border-brand-200 bg-gradient-to-r from-brand-50 to-white px-4 py-3 text-sm text-brand-900 shadow-sm hover:border-brand-300">
        <Sparkles className="size-5 text-brand-600" />
        <span className="flex-1">
          <b>Ask your network.</b> “Kaç switch var?”, “HP yazıcıları göster”, “Laboratuvarda Windows XP kullanan cihazlar”…
        </span>
        <ArrowRight className="size-4" />
      </Link>
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Device types">
          <Bars rows={d.by_type.map((r) => ({ label: <span className="inline-flex items-center gap-1.5"><DeviceIcon type={r.type} />{typeLabel(r.type)}</span>, value: r.count, color: TYPE_COLORS[r.type], to: `/devices?type=${r.type}` }))} />
        </Card>
        <Card title="Vendors">
          <Bars rows={d.by_vendor.map((r) => ({ label: r.vendor, value: r.count, to: r.vendor !== 'Unknown' ? `/devices?vendor=${encodeURIComponent(r.vendor)}` : undefined }))} color="#475569" />
        </Card>
        <Card title="Operating systems">
          {d.by_os.length ? <Bars rows={d.by_os.map((r) => ({ label: r.os, value: r.count }))} color="#6366f1" /> : <Empty title="No operating systems identified yet" />}
        </Card>
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Recent events" className="lg:col-span-2" actions={<Link className="text-xs text-brand-700 hover:underline" to="/events">All events</Link>} padded={false}>
          <ul className="divide-y divide-slate-100">
            {d.recent_events.map((e) => (
              <li key={e.id} className="flex items-center gap-3 px-4 py-2 text-sm">
                <Badge tone={sevTone(e.severity)}>{e.severity}</Badge>
                <span className="min-w-0 flex-1 truncate">
                  {e.device_id ? <Link to={`/devices/${e.device_id}`} className="font-medium hover:underline">{e.device}</Link> : null} {e.message}
                </span>
                <span className="whitespace-nowrap text-xs text-slate-400">{ago(e.ts)}</span>
              </li>
            ))}
            {!d.recent_events.length && <li className="px-4 py-6 text-center text-sm text-slate-400">No events yet</li>}
          </ul>
        </Card>
        <div className="space-y-5">
          <Card title="Discovery runs" actions={<Link className="text-xs text-brand-700 hover:underline" to="/discovery">History</Link>} padded={false}>
            <ul className="divide-y divide-slate-100">
              {d.recent_runs?.map((r) => (
                <li key={r.id} className="flex items-center justify-between px-4 py-2 text-sm">
                  <span className="font-mono text-xs">{r.seed_ip}</span>
                  <span className="flex items-center gap-2">
                    <Badge tone={r.status === 'completed' ? 'green' : r.status === 'failed' ? 'red' : 'blue'}>{r.status}</Badge>
                    <span className="text-xs text-slate-400">{ago(r.created_at)}</span>
                  </span>
                </li>
              ))}
            </ul>
          </Card>
          <Card title="Busiest ports" padded={false}>
            <ul className="divide-y divide-slate-100">
              {d.top_ports?.map((p) => (
                <li key={p.id} className="flex items-center justify-between gap-2 px-4 py-2 text-sm">
                  <Link to={`/devices/${p.device_id}`} className="min-w-0 truncate hover:underline">
                    {p.device} <span className="text-slate-400">{p.port}</span>
                  </Link>
                  <span className="whitespace-nowrap tabular-nums text-slate-600">{bps(p.bps)}</span>
                </li>
              ))}
              {!d.top_ports?.length && <li className="px-4 py-4 text-center text-xs text-slate-400">Traffic rates appear after the second poll</li>}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  )
}
