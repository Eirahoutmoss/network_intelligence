import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '@/api/client'
import type { NetEvent } from '@/api/types'
import { Badge, Card, Empty, Input, Loading, PageHeader, Select, Table, Td, Th } from '@/components/ui'
import { dateTime } from '@/lib/format'
import { sevTone } from './Dashboard'

export default function Events() {
  const q = useQuery({ queryKey: ['events'], queryFn: () => api.get<NetEvent[]>('/api/events?limit=500'), refetchInterval: 30_000 })
  const [sev, setSev] = useState('')
  const [text, setText] = useState('')
  const rows = (q.data ?? []).filter((e) => (!sev || e.severity === sev) && (!text || `${e.device} ${e.message} ${e.kind}`.toLowerCase().includes(text.toLowerCase())))
  return (
    <div className="p-6">
      <PageHeader title="Events" subtitle="What changed on the network: new devices, moves, link changes, discovery runs" />
      <Card padded={false}>
        <div className="flex gap-2 border-b border-slate-100 p-3">
          <Input value={text} onChange={(e) => setText(e.target.value)} placeholder="Filter" className="max-w-xs" />
          <Select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">All severities</option><option value="info">Info</option><option value="warning">Warning</option><option value="critical">Critical</option>
          </Select>
        </div>
        {q.isLoading ? <Loading /> : !rows.length ? <Empty title="No events" /> : (
          <Table>
            <thead><tr><Th>Time</Th><Th>Severity</Th><Th>Device</Th><Th>Event</Th><Th>Kind</Th></tr></thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}>
                  <Td className="whitespace-nowrap text-xs text-slate-500">{dateTime(e.ts)}</Td>
                  <Td><Badge tone={sevTone(e.severity)}>{e.severity}</Badge></Td>
                  <Td>{e.device_id ? <Link to={`/devices/${e.device_id}`} className="hover:underline">{e.device}</Link> : '—'}</Td>
                  <Td>{e.message}</Td>
                  <Td className="font-mono text-xs text-slate-500">{e.kind}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  )
}
