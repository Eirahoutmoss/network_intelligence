import {
  Activity,
  Bell,
  BarChart3,
  Cable,
  LayoutDashboard,
  LogOut,
  MapPin,
  Monitor,
  Network,
  Plus,
  Printer,
  Search,
  Server,
  Settings,
  Share2,
  Sparkles,
} from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Alert } from '@/api/types'
import { useAuth } from '@/lib/auth'
import { AddDeviceDialog } from './AddDeviceDialog'
import { Button, cn } from './ui'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/explore', label: 'Explore Network', icon: Sparkles },
  { to: '/topology', label: 'Topology', icon: Share2 },
  { to: '/devices', label: 'Devices', icon: Server, end: true },
  { to: '/connections', label: 'Connections', icon: Cable },
  { to: '/locations', label: 'Locations', icon: MapPin },
  { to: '/devices/printers', label: 'Printers', icon: Printer },
  { to: '/devices/computers', label: 'Computers', icon: Monitor },
  { to: '/alerts', label: 'Alerts', icon: Bell, badge: true },
  { to: '/events', label: 'Events', icon: Activity },
  { to: '/reports', label: 'Reports', icon: BarChart3 },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout, can, info } = useAuth()
  const [adding, setAdding] = useState(false)
  const [q, setQ] = useState('')
  const navigate = useNavigate()
  const alerts = useQuery({ queryKey: ['alerts', 'open'], queryFn: () => api.get<Alert[]>('/api/alerts'), refetchInterval: 30_000 })
  const openAlerts = alerts.data?.length ?? 0

  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col bg-slate-900 text-slate-300">
        <div className="flex items-center gap-2.5 px-5 py-4">
          <div className="grid size-8 place-items-center rounded-lg bg-brand-600 text-white">
            <Network className="size-4.5" />
          </div>
          <div>
            <div className="text-sm font-semibold text-white">Nexus</div>
            <div className="text-[11px] text-slate-400">Network Intelligence</div>
          </div>
        </div>
        {can('operator') && (
          <div className="px-3 pb-3">
            <Button variant="primary" className="w-full" onClick={() => setAdding(true)}>
              <Plus className="size-4" /> Add Device
            </Button>
          </div>
        )}
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 pb-4">
          {nav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors',
                  isActive ? 'bg-slate-800 text-white' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200',
                )
              }
            >
              <n.icon className="size-4" />
              <span className="flex-1">{n.label}</span>
              {n.badge && openAlerts > 0 && <span className="rounded-full bg-red-500 px-1.5 text-[11px] font-semibold text-white">{openAlerts}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-800 px-4 py-3 text-xs">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-slate-200">{user?.username}</div>
              <div className="text-slate-500">{user?.role}</div>
            </div>
            <button onClick={logout} className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white" title="Sign out">
              <LogOut className="size-4" />
            </button>
          </div>
          {info && <div className="mt-2 text-[11px] text-slate-600">v{info.version}</div>}
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-slate-200 bg-white px-6">
          <form
            className="relative max-w-xl flex-1"
            onSubmit={(e) => {
              e.preventDefault()
              if (q.trim()) navigate(`/explore?q=${encodeURIComponent(q.trim())}`)
            }}
          >
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder='Ask your network… e.g. "Kaç switch var?" or "HP printers on floor 2"'
              className="h-9 w-full rounded-lg border border-slate-200 bg-slate-50 pl-9 pr-3 text-sm placeholder:text-slate-400 focus:border-brand-500 focus:bg-white focus:outline-none focus:ring-2 focus:ring-brand-500/20"
            />
          </form>
          {info?.simulator && (
            <span className="rounded-md bg-amber-50 px-2 py-1 text-xs font-medium text-amber-800 ring-1 ring-amber-200" title="A simulated campus network is active for evaluation">
              Demo network active
            </span>
          )}
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">{children}</main>
      </div>
      <AddDeviceDialog open={adding} onClose={() => setAdding(false)} />
    </div>
  )
}
