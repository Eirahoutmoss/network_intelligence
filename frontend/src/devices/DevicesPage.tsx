import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, MapPin, Server } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, qs } from '@/api/client'
import type { DeviceRow, Location } from '@/api/types'
import { Button, Card, Empty, ErrorBox, Input, Loading, Modal, PageHeader, Select } from '@/components/ui'
import { DEVICE_TYPES, typeLabel } from '@/lib/format'
import { useAuth } from '@/lib/auth'
import { DeviceTable } from './DeviceTable'

export default function DevicesPage({ preset }: { preset?: string }) {
  const [params, setParams] = useSearchParams()
  const { can } = useAuth()
  const [text, setText] = useState(params.get('q') ?? '')
  const type = preset ?? params.get('type') ?? ''
  const vendor = params.get('vendor') ?? ''
  const status = params.get('status') ?? ''
  const managed = params.get('managed') ?? ''
  const locationId = params.get('location_id') ?? ''
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [assigning, setAssigning] = useState(false)
  const limit = 100
  useEffect(() => setPage(0), [type, vendor, status, managed, locationId, params])
  useEffect(() => {
    const h = setTimeout(() => {
      if (text !== (params.get('q') ?? '')) update('q', text)
    }, 300)
    return () => clearTimeout(h)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text])
  const update = (k: string, v: string) => {
    const p = new URLSearchParams(params)
    if (v) p.set(k, v)
    else p.delete(k)
    setParams(p, { replace: true })
  }
  const q = useQuery({
    queryKey: ['devices', type, vendor, status, managed, locationId, params.get('q'), page],
    queryFn: () =>
      api.get<{ devices: DeviceRow[]; total: number }>(
        '/api/devices' + qs({ type, vendor, status, managed, location_id: locationId, q: params.get('q') ?? '', limit, offset: page * limit }),
      ),
    placeholderData: keepPreviousData,
  })
  const locs = useQuery({ queryKey: ['locations'], queryFn: () => api.get<Location[]>('/api/locations') })
  const title = preset === 'printer' ? 'Printers' : preset === 'computer' ? 'Computers' : 'Devices'
  const total = q.data?.total ?? 0
  return (
    <div className="p-6">
      <PageHeader
        title={title}
        subtitle={`${total} ${total === 1 ? 'device' : 'devices'}`}
        actions={
          <>
            {can('operator') && selected.size > 0 && (
              <Button onClick={() => setAssigning(true)}>
                <MapPin className="size-4" /> Set location ({selected.size})
              </Button>
            )}
            <a href="/api/reports/inventory.csv">
              <Button>
                <Download className="size-4" /> Export CSV
              </Button>
            </a>
          </>
        }
      />
      <Card padded={false}>
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 p-3">
          <Input value={text} onChange={(e) => setText(e.target.value)} placeholder="Search name, IP, MAC, vendor, model…" className="max-w-xs" />
          {!preset && (
            <Select value={type} onChange={(e) => update('type', e.target.value)}>
              <option value="">All types</option>
              {DEVICE_TYPES.map((t) => (
                <option key={t} value={t}>{typeLabel(t)}</option>
              ))}
            </Select>
          )}
          <Input value={vendor} onChange={(e) => update('vendor', e.target.value)} placeholder="Vendor" className="w-32" />
          <Select value={status} onChange={(e) => update('status', e.target.value)}>
            <option value="">Any status</option>
            <option value="up">Up</option>
            <option value="down">Down</option>
          </Select>
          <Select value={managed} onChange={(e) => update('managed', e.target.value)}>
            <option value="">Network + endpoints</option>
            <option value="true">Network devices (SNMP)</option>
            <option value="false">Endpoints</option>
          </Select>
          <Select value={locationId} onChange={(e) => update('location_id', e.target.value)}>
            <option value="">Any location</option>
            {locs.data?.map((l) => (
              <option key={l.id} value={l.id}>{l.path}</option>
            ))}
          </Select>
        </div>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <div className="p-4"><ErrorBox error={q.error} /></div>
        ) : !q.data?.devices.length ? (
          <Empty icon={<Server className="size-10" />} title="No devices match">Try removing a filter, or add a device to start discovery.</Empty>
        ) : (
          <>
            <DeviceTable
              rows={q.data.devices}
              selectable={can('operator')}
              selected={selected}
              onSelect={(id, on) => setSelected((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n })}
            />
            {total > limit && (
              <div className="flex items-center justify-between px-4 py-3 text-sm text-slate-500">
                <span>{page * limit + 1}–{Math.min(total, (page + 1) * limit)} of {total}</span>
                <div className="flex gap-2">
                  <Button size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Button>
                  <Button size="sm" disabled={(page + 1) * limit >= total} onClick={() => setPage(page + 1)}>Next</Button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>
      <AssignLocation open={assigning} ids={[...selected]} locations={locs.data ?? []} onClose={() => { setAssigning(false); setSelected(new Set()) }} />
    </div>
  )
}

function AssignLocation({ open, ids, locations, onClose }: { open: boolean; ids: number[]; locations: Location[]; onClose: () => void }) {
  const [loc, setLoc] = useState('')
  const [err, setErr] = useState<unknown>(null)
  const qc = useQueryClient()
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`Set location for ${ids.length} devices`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            onClick={async () => {
              try {
                await api.post('/api/devices/assign-location', { device_ids: ids, location_id: loc ? Number(loc) : null })
                qc.invalidateQueries({ queryKey: ['devices'] })
                onClose()
              } catch (e) {
                setErr(e)
              }
            }}
          >
            Save
          </Button>
        </>
      }
    >
      <Select value={loc} onChange={(e) => setLoc(e.target.value)} className="w-full">
        <option value="">— No location —</option>
        {locations.map((l) => (
          <option key={l.id} value={l.id}>{l.path}</option>
        ))}
      </Select>
      <ErrorBox error={err} />
    </Modal>
  )
}
