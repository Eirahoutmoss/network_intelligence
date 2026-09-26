import { useQuery } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { Link } from 'react-router-dom'
import { api } from '@/api/client'
import { DeviceIcon } from '@/components/DeviceIcon'
import { Badge, Button, Card, Confidence, Empty, Loading, PageHeader, Table, Td, Th } from '@/components/ui'
import { typeLabel } from '@/lib/format'

interface Summary {
  type_vendor: { type: string; vendor: string; count: number }[]
  os: { os: string; count: number; avg_confidence: number }[]
  legacy_os: { id: number; name: string; os_name: string; os_confidence: number; ip: string | null; location_path: string | null }[]
  firmware: { vendor: string; model: string; version: string; count: number }[]
  port_usage: { id: number; switch: string; ports: number; up: number; free: number }[]
  unknown_devices: { id: number; name: string; vendor: string | null; ip: string | null; mac: string | null; switch_name: string | null; switch_port: string | null }[]
}

export default function Reports() {
  const q = useQuery({ queryKey: ['report-summary'], queryFn: () => api.get<Summary>('/api/reports/summary') })
  if (q.isLoading) return <Loading />
  const s = q.data
  if (!s) return null
  return (
    <div className="space-y-5 p-6">
      <PageHeader title="Reports" subtitle="Inventory, lifecycle and capacity at a glance"
        actions={<a href="/api/reports/inventory.csv"><Button><Download className="size-4" /> Full inventory (CSV)</Button></a>} />
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Inventory by type and vendor" padded={false}>
          <div className="max-h-96 overflow-auto">
            <Table>
              <thead><tr><Th>Type</Th><Th>Vendor</Th><Th className="text-right">Count</Th></tr></thead>
              <tbody>{s.type_vendor.map((r, i) => (
                <tr key={i}><Td><span className="inline-flex items-center gap-1.5"><DeviceIcon type={r.type} />{typeLabel(r.type)}</span></Td><Td>{r.vendor}</Td>
                  <Td className="text-right tabular-nums"><Link className="hover:underline" to={`/devices?type=${r.type}${r.vendor !== 'Unknown' ? `&vendor=${encodeURIComponent(r.vendor)}` : ''}`}>{r.count}</Link></Td></tr>
              ))}</tbody>
            </Table>
          </div>
        </Card>
        <Card title="Legacy operating systems" padded={false}>
          {s.legacy_os?.length ? (
            <Table>
              <thead><tr><Th>Device</Th><Th>OS</Th><Th>IP</Th><Th>Location</Th></tr></thead>
              <tbody>{s.legacy_os.map((d) => (
                <tr key={d.id}><Td><Link className="font-medium hover:underline" to={`/devices/${d.id}`}>{d.name}</Link></Td>
                  <Td><span className="inline-flex items-center gap-1.5">{d.os_name}<Confidence value={d.os_confidence} /></span></Td>
                  <Td className="font-mono text-xs">{d.ip}</Td><Td className="text-xs">{d.location_path ?? '—'}</Td></tr>
              ))}</tbody>
            </Table>
          ) : <Empty title="No unsupported Windows versions detected" />}
        </Card>
        <Card title="Switch port capacity" padded={false}>
          <Table>
            <thead><tr><Th>Switch</Th><Th className="text-right">Ports</Th><Th className="text-right">In use</Th><Th className="text-right">Free</Th><Th>Usage</Th></tr></thead>
            <tbody>{s.port_usage?.map((p) => (
              <tr key={p.id}><Td><Link className="hover:underline" to={`/devices/${p.id}`}>{p.switch}</Link></Td>
                <Td className="text-right tabular-nums">{p.ports}</Td><Td className="text-right tabular-nums">{p.up}</Td><Td className="text-right tabular-nums">{p.free}</Td>
                <Td><div className="h-2 w-28 rounded-full bg-slate-100"><div className="h-2 rounded-full bg-brand-600" style={{ width: `${p.ports ? (p.up / p.ports) * 100 : 0}%` }} /></div></Td></tr>
            ))}</tbody>
          </Table>
        </Card>
        <Card title="Network device software" padded={false}>
          <Table>
            <thead><tr><Th>Vendor</Th><Th>Model</Th><Th>Software</Th><Th className="text-right">Count</Th></tr></thead>
            <tbody>{s.firmware?.map((f, i) => (
              <tr key={i}><Td>{f.vendor}</Td><Td>{f.model}</Td><Td className="font-mono text-xs">{f.version}</Td><Td className="text-right">{f.count}</Td></tr>
            ))}</tbody>
          </Table>
        </Card>
        <Card title="Operating systems (endpoints)" padded={false}>
          <Table>
            <thead><tr><Th>OS</Th><Th className="text-right">Devices</Th><Th className="text-right">Avg. confidence</Th></tr></thead>
            <tbody>{s.os?.map((o, i) => (
              <tr key={i}><Td>{o.os}</Td><Td className="text-right">{o.count}</Td><Td className="text-right">{o.avg_confidence ? <Confidence value={Number(o.avg_confidence)} /> : '—'}</Td></tr>
            ))}</tbody>
          </Table>
        </Card>
        <Card title={<>Unidentified devices <Badge>{s.unknown_devices?.length ?? 0}</Badge></>} padded={false}>
          {s.unknown_devices?.length ? (
            <div className="max-h-96 overflow-auto">
              <Table>
                <thead><tr><Th>Device</Th><Th>Vendor</Th><Th>Switch port</Th></tr></thead>
                <tbody>{s.unknown_devices.map((d) => (
                  <tr key={d.id}><Td><Link className="hover:underline" to={`/devices/${d.id}`}>{d.name}</Link><div className="font-mono text-xs text-slate-400">{d.mac}</div></Td>
                    <Td>{d.vendor ?? '—'}</Td><Td className="text-xs">{d.switch_name} {d.switch_port}</Td></tr>
                ))}</tbody>
              </Table>
            </div>
          ) : <Empty title="Every device has a type" />}
        </Card>
      </div>
    </div>
  )
}
