import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '@/api/client'
import type { DiscoveryRun } from '@/api/types'
import { DiscoveryProgress, useRunStream } from '@/components/DiscoveryProgress'
import { Badge, Button, Card, Empty, Loading, PageHeader, Table, Td, Th } from '@/components/ui'
import { dateTime } from '@/lib/format'
import { useAuth } from '@/lib/auth'

export default function Discovery() {
  const q = useQuery({ queryKey: ['runs'], queryFn: () => api.get<DiscoveryRun[]>('/api/discovery/runs'), refetchInterval: 5000 })
  const [open, setOpen] = useState<number | null>(null)
  const run = useRunStream(open)
  const { can } = useAuth()
  return (
    <div className="p-6">
      <PageHeader title="Discovery runs" subtitle="Every discovery with its scope, progress and results" />
      <div className="grid gap-5 lg:grid-cols-2">
        <Card padded={false}>
          {q.isLoading ? <Loading /> : !q.data?.length ? <Empty title="No discovery yet" /> : (
            <Table>
              <thead><tr><Th>#</Th><Th>Seed</Th><Th>Scope</Th><Th>Status</Th><Th>Result</Th><Th>Started</Th></tr></thead>
              <tbody>
                {q.data.map((r) => (
                  <tr key={r.id} onClick={() => setOpen(r.id)} className={`cursor-pointer hover:bg-slate-50 ${open === r.id ? 'bg-brand-50/50' : ''}`}>
                    <Td>{r.id}</Td>
                    <Td className="font-mono text-xs">{r.options?.targets ? `refresh (${r.options.targets.length})` : r.seed_ip}</Td>
                    <Td className="text-xs">{r.scope.slice(0, 2).join(', ')}{r.scope.length > 2 ? '…' : ''} · {r.max_depth} hops</Td>
                    <Td><Badge tone={r.status === 'completed' ? 'green' : r.status === 'failed' ? 'red' : r.status === 'cancelled' ? 'slate' : 'blue'}>{r.status}</Badge></Td>
                    <Td className="text-xs">{r.summary?.devices ?? 0} devices · {r.summary?.endpoints ?? 0} endpoints</Td>
                    <Td className="text-xs text-slate-500">{dateTime(r.created_at)}<div>{r.created_by}</div></Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
        <Card title={open ? `Run #${open}` : 'Details'} actions={open && run && (run.status === 'running' || run.status === 'queued') && can('operator') && (
          <Button size="sm" variant="danger" onClick={() => api.post(`/api/discovery/runs/${open}/cancel`)}>Cancel</Button>
        )}>
          {open ? <DiscoveryProgress run={run} /> : <div className="text-sm text-slate-500">Select a run to see its steps.</div>}
        </Card>
      </div>
    </div>
  )
}
