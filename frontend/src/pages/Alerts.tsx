import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Bell } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '@/api/client'
import type { Alert } from '@/api/types'
import { Badge, Button, Card, Empty, Loading, PageHeader, Table, Td, Th } from '@/components/ui'
import { ago, dateTime } from '@/lib/format'
import { useAuth } from '@/lib/auth'
import { sevTone } from './Dashboard'

export default function Alerts() {
  const [all, setAll] = useState(false)
  const { can } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['alerts', all ? 'all' : 'open'], queryFn: () => api.get<Alert[]>(`/api/alerts${all ? '?all=true' : ''}`), refetchInterval: 30_000 })
  return (
    <div className="p-6">
      <PageHeader title="Alerts" subtitle="Problems that need attention. Alerts close automatically when the condition clears."
        actions={<Button onClick={() => setAll(!all)}>{all ? 'Show open only' : 'Show history'}</Button>} />
      <Card padded={false}>
        {q.isLoading ? <Loading /> : !q.data?.length ? <Empty icon={<Bell className="size-10" />} title="No alerts">Everything that Nexus monitors looks healthy.</Empty> : (
          <Table>
            <thead><tr><Th>Severity</Th><Th>Device</Th><Th>Problem</Th><Th>Opened</Th><Th>Status</Th><Th /></tr></thead>
            <tbody>
              {q.data.map((a) => (
                <tr key={a.id}>
                  <Td><Badge tone={sevTone(a.severity)}>{a.severity}</Badge></Td>
                  <Td>{a.device_id ? <Link className="font-medium hover:underline" to={`/devices/${a.device_id}`}>{a.device}</Link> : '—'}</Td>
                  <Td>{a.message}</Td>
                  <Td className="text-xs text-slate-500" title={dateTime(a.opened_at)}>{ago(a.opened_at)}</Td>
                  <Td>{a.resolved_at ? <Badge tone="green">resolved {ago(a.resolved_at)}</Badge> : a.acknowledged ? <Badge tone="blue">acknowledged</Badge> : <Badge tone="red">open</Badge>}</Td>
                  <Td>{!a.resolved_at && !a.acknowledged && can('operator') && (
                    <Button size="sm" onClick={async () => { await api.post(`/api/alerts/${a.id}/ack`); qc.invalidateQueries({ queryKey: ['alerts'] }) }}>Acknowledge</Button>
                  )}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  )
}
