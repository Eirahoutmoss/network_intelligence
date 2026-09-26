import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, qs } from '@/api/client'
import { DeviceIcon } from '@/components/DeviceIcon'
import { Badge, Card, Confidence, Empty, Loading, PageHeader, Select, Table, Td, Th } from '@/components/ui'
import { ago, speed } from '@/lib/format'

interface Conn {
  id: number; layer: string; a_id: number; a_name: string; a_port: string | null; a_type: string
  b_id: number; b_name: string; b_port: string | null; b_type: string; medium: string | null; speed_bps: number | null
  sources: string[]; confidence: number; updated_at: string; manual: boolean
}

export default function Connections() {
  const [medium, setMedium] = useState('')
  const [infra, setInfra] = useState(true)
  const q = useQuery({ queryKey: ['connections', medium, infra], queryFn: () => api.get<Conn[]>('/api/connections' + qs({ medium, infra, layer: 'physical' })) })
  return (
    <div className="p-6">
      <PageHeader title="Connections" subtitle="Physical links between devices, as discovered from LLDP/CDP, MAC tables and your own additions"
        actions={
          <>
            <Select value={medium} onChange={(e) => setMedium(e.target.value)}>
              <option value="">Any medium</option><option value="fiber">Fiber</option><option value="copper">Copper</option><option value="unknown">Unknown</option>
            </Select>
            <Select value={infra ? 'infra' : 'all'} onChange={(e) => setInfra(e.target.value === 'infra')}>
              <option value="infra">Between network devices</option><option value="all">Including endpoints</option>
            </Select>
          </>
        } />
      <Card padded={false}>
        {q.isLoading ? <Loading /> : !q.data?.length ? <Empty title="No connections found" /> : (
          <Table>
            <thead><tr><Th>Device A</Th><Th>Port</Th><Th>Device B</Th><Th>Port</Th><Th>Medium</Th><Th>Speed</Th><Th>Source</Th><Th>Certainty</Th><Th>Updated</Th></tr></thead>
            <tbody>
              {q.data.map((c) => (
                <tr key={`${c.manual}-${c.id}`} className="hover:bg-slate-50/70">
                  <Td><Link to={`/devices/${c.a_id}`} className="inline-flex items-center gap-1.5 font-medium hover:underline"><DeviceIcon type={c.a_type} />{c.a_name}</Link></Td>
                  <Td className="text-slate-500">{c.a_port}</Td>
                  <Td><Link to={`/devices/${c.b_id}`} className="inline-flex items-center gap-1.5 font-medium hover:underline"><DeviceIcon type={c.b_type} />{c.b_name}</Link></Td>
                  <Td className="text-slate-500">{c.b_port}</Td>
                  <Td>{c.medium && c.medium !== 'unknown' ? <Badge tone={c.medium === 'fiber' ? 'blue' : 'slate'}>{c.medium}</Badge> : <span className="text-slate-400">—</span>}</Td>
                  <Td>{speed(c.speed_bps)}</Td>
                  <Td>{c.sources.map((s) => <Badge key={s} className="mr-1">{s}</Badge>)}</Td>
                  <Td><Confidence value={c.confidence} /></Td>
                  <Td className="text-xs text-slate-500">{ago(c.updated_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  )
}
