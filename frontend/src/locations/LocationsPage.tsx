import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2, ChevronRight, DoorOpen, Download, Layers, MapPin, Pencil, Plug, Plus, Server, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '@/api/client'
import type { DeviceRow, Interface, Jack, Location, PatchPanel, Rack } from '@/api/types'
import { Badge, Button, Card, cn, Empty, ErrorBox, Field, Input, Loading, Modal, PageHeader, Select, Table, Td, Th } from '@/components/ui'
import { DeviceTable } from '@/devices/DeviceTable'
import { useAuth } from '@/lib/auth'

const KIND_ICON = { site: MapPin, building: Building2, floor: Layers, room: DoorOpen, closet: Server, area: MapPin }
const CHILD_KIND: Record<string, Location['kind']> = { site: 'building', building: 'floor', floor: 'room', room: 'area', closet: 'area', area: 'area' }

export default function LocationsPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const locs = useQuery({ queryKey: ['locations'], queryFn: () => api.get<Location[]>('/api/locations') })
  const [sel, setSel] = useState<number | null>(null)
  const [edit, setEdit] = useState<Partial<Location> | null>(null)
  const [importMsg, setImportMsg] = useState<string | null>(null)
  const children = useMemo(() => {
    const m = new Map<number | null, Location[]>()
    for (const l of locs.data ?? []) m.set(l.parent_id, [...(m.get(l.parent_id) ?? []), l])
    return m
  }, [locs.data])
  const selected = locs.data?.find((l) => l.id === sel) ?? null
  const refresh = () => qc.invalidateQueries({ queryKey: ['locations'] })

  const Tree = ({ parent, depth }: { parent: number | null; depth: number }) => (
    <ul>
      {(children.get(parent) ?? []).sort((a, b) => (a.level ?? 0) - (b.level ?? 0) || a.name.localeCompare(b.name)).map((l) => {
        const Icon = KIND_ICON[l.kind]
        return (
          <li key={l.id}>
            <button
              onClick={() => setSel(l.id)}
              className={cn('flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-slate-100', sel === l.id && 'bg-brand-50 text-brand-900')}
              style={{ paddingLeft: 8 + depth * 16 }}
            >
              {children.get(l.id) ? <ChevronRight className="size-3 text-slate-400" /> : <span className="w-3" />}
              <Icon className="size-4 text-slate-500" />
              <span className="flex-1 truncate">{l.name}</span>
              {l.device_count > 0 && <span className="text-xs text-slate-400">{l.device_count}</span>}
            </button>
            {children.get(l.id) && <Tree parent={l.id} depth={depth + 1} />}
          </li>
        )
      })}
    </ul>
  )

  return (
    <div className="p-6">
      <PageHeader
        title="Locations"
        subtitle="Buildings, floors, rooms, racks and wall jacks. This is your context — Nexus combines it with what it discovers."
        actions={can('operator') && (
          <>
            <Button onClick={async () => {
              const r = await api.post<{ created: number; assigned: number }>('/api/locations/import-syslocation')
              setImportMsg(`Created ${r.created} locations and placed ${r.assigned} network devices from their SNMP location.`)
              refresh()
              qc.invalidateQueries({ queryKey: ['devices'] })
            }}>
              <Download className="size-4" /> Import from SNMP location
            </Button>
            <Button variant="primary" onClick={() => setEdit({ kind: 'building', parent_id: null })}><Plus className="size-4" /> Add building</Button>
          </>
        )}
      />
      {importMsg && <div className="mb-4 rounded-lg bg-emerald-50 px-3 py-2 text-sm text-emerald-800 ring-1 ring-emerald-200">{importMsg}</div>}
      <div className="grid gap-5 lg:grid-cols-[18rem_1fr]">
        <Card padded={false} className="h-fit">
          <div className="p-2">
            {locs.isLoading ? <Loading /> : !locs.data?.length ? (
              <Empty icon={<Building2 className="size-8" />} title="No locations yet">Add a building, or import the structure from the SNMP location strings of your switches.</Empty>
            ) : <Tree parent={null} depth={0} />}
          </div>
        </Card>
        {selected ? (
          <LocationDetail loc={selected} all={locs.data ?? []} onEdit={() => setEdit(selected)} onAddChild={() => setEdit({ kind: CHILD_KIND[selected.kind], parent_id: selected.id })}
            onDelete={async () => {
              if (!confirm(`Delete ${selected.name} and everything inside it? Devices keep their data but lose this placement.`)) return
              await api.del(`/api/locations/${selected.id}`)
              setSel(null)
              refresh()
            }} />
        ) : (
          <Card><Empty icon={<MapPin className="size-10" />} title="Select a location">See the devices, racks and wall jacks it contains.</Empty></Card>
        )}
      </div>
      <LocationForm value={edit} all={locs.data ?? []} onClose={() => setEdit(null)} onSaved={(id) => { refresh(); if (id) setSel(id) }} />
    </div>
  )
}

function LocationForm({ value, all, onClose, onSaved }: { value: Partial<Location> | null; all: Location[]; onClose: () => void; onSaved: (id?: number) => void }) {
  const [v, setV] = useState<Partial<Location>>({})
  const [err, setErr] = useState<unknown>(null)
  const open = !!value
  useEffect(() => {
    if (value) setV({ ...value })
  }, [value])
  return (
    <Modal open={open} onClose={() => { setV({}); onClose() }} title={value?.id ? 'Edit location' : 'New location'} footer={
      <>
        <Button variant="ghost" onClick={() => { setV({}); onClose() }}>Cancel</Button>
        <Button variant="primary" onClick={async () => {
          try {
            const body = { kind: v.kind, name: v.name, parent_id: v.parent_id ?? null, description: v.description ?? null, level: v.level === undefined || (v.level as unknown) === '' ? null : Number(v.level) }
            let id = v.id
            if (v.id) await api.put(`/api/locations/${v.id}`, body)
            else id = (await api.post<{ id: number }>('/api/locations', body)).id
            setV({})
            onSaved(id)
            onClose()
          } catch (e) { setErr(e) }
        }}>Save</Button>
      </>
    }>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Name" className="col-span-2"><Input autoFocus value={v.name ?? ''} onChange={(e) => setV({ ...v, name: e.target.value })} placeholder="Building A / Floor 2 / Room 214" /></Field>
        <Field label="Kind">
          <Select value={v.kind ?? 'building'} onChange={(e) => setV({ ...v, kind: e.target.value as Location['kind'] })} className="w-full">
            {['site', 'building', 'floor', 'room', 'closet', 'area'].map((k) => <option key={k} value={k}>{k}</option>)}
          </Select>
        </Field>
        {v.kind === 'floor' && <Field label="Floor number" hint="Used by questions like “Kat 2”"><Input value={v.level ?? ''} onChange={(e) => setV({ ...v, level: e.target.value === '' ? null : Number(e.target.value) })} /></Field>}
        <Field label="Inside" className="col-span-2">
          <Select value={v.parent_id ?? ''} onChange={(e) => setV({ ...v, parent_id: e.target.value ? Number(e.target.value) : null })} className="w-full">
            <option value="">— top level —</option>
            {all.filter((l) => l.id !== v.id).map((l) => <option key={l.id} value={l.id}>{l.path}</option>)}
          </Select>
        </Field>
        <Field label="Description" className="col-span-2"><Input value={v.description ?? ''} onChange={(e) => setV({ ...v, description: e.target.value })} /></Field>
      </div>
      <ErrorBox error={err} />
    </Modal>
  )
}

function LocationDetail({ loc, all, onEdit, onAddChild, onDelete }: { loc: Location; all: Location[]; onEdit: () => void; onAddChild: () => void; onDelete: () => void }) {
  const { can } = useAuth()
  const devices = useQuery({ queryKey: ['devices', 'loc', loc.id], queryFn: () => api.get<{ devices: DeviceRow[]; total: number }>(`/api/devices?location_id=${loc.id}&limit=500`) })
  const jacks = useQuery({ queryKey: ['jacks', loc.id], queryFn: () => api.get<Jack[]>(`/api/jacks?location_id=${loc.id}`) })
  const racks = useQuery({ queryKey: ['racks'], queryFn: () => api.get<Rack[]>('/api/racks') })
  const panels = useQuery({ queryKey: ['patch-panels'], queryFn: () => api.get<PatchPanel[]>('/api/patch-panels') })
  const [jackEdit, setJackEdit] = useState<Partial<Jack> | null>(null)
  const [newRack, setNewRack] = useState(false)
  const [newPanel, setNewPanel] = useState(false)
  const qc = useQueryClient()
  const inLoc = (id: number) => all.find((l) => l.id === id)?.path.startsWith(loc.path)
  const myRacks = racks.data?.filter((r) => inLoc(r.location_id)) ?? []
  const myPanels = panels.data?.filter((p) => inLoc(p.location_id)) ?? []
  return (
    <div className="space-y-5">
      <Card title={<span className="flex items-center gap-2">{loc.path} <Badge>{loc.kind}</Badge></span>} actions={can('operator') && (
        <>
          <Button size="sm" onClick={onAddChild}><Plus className="size-3.5" /> Add inside</Button>
          <Button size="sm" onClick={onEdit}><Pencil className="size-3.5" /> Edit</Button>
          <Button size="sm" variant="ghost" onClick={onDelete}><Trash2 className="size-3.5 text-red-600" /></Button>
        </>
      )}>
        <div className="flex flex-wrap gap-6 text-sm text-slate-600">
          <span><b className="text-slate-900">{devices.data?.total ?? '…'}</b> devices</span>
          <span><b className="text-slate-900">{jacks.data?.length ?? '…'}</b> wall jacks</span>
          <span><b className="text-slate-900">{myRacks.length}</b> racks</span>
          <span><b className="text-slate-900">{myPanels.length}</b> patch panels</span>
          <Link className="text-brand-700 hover:underline" to={`/topology?location=${loc.id}`}>View on topology →</Link>
        </div>
        {loc.description && <p className="mt-2 text-sm text-slate-500">{loc.description}</p>}
      </Card>
      <Card title="Wall jacks" padded={false} actions={can('operator') && <Button size="sm" onClick={() => setJackEdit({ location_id: loc.id })}><Plug className="size-3.5" /> Add jack</Button>}>
        {!jacks.data?.length ? <Empty title="No wall jacks">Map a wall jack (e.g. “214-07”) to its patch panel port and switch port. Then you can ask “Room 214 jack 07'ye ne bağlı?”.</Empty> : (
          <Table>
            <thead><tr><Th>Jack</Th><Th>Room</Th><Th>Patch panel</Th><Th>Switch port</Th><Th>Now connected</Th><Th /></tr></thead>
            <tbody>
              {jacks.data.map((j) => (
                <tr key={j.id}>
                  <Td className="font-medium">{j.label}</Td>
                  <Td className="text-xs">{j.location}</Td>
                  <Td>{j.patch_panel ? `${j.patch_panel} / ${j.patch_port ?? '?'}` : '—'}</Td>
                  <Td>{j.switch ? <Link className="hover:underline" to={`/devices/${j.switch_device_id}`}>{j.switch} <span className="text-slate-500">{j.port}</span></Link> : <span className="text-amber-600">not mapped</span>}</Td>
                  <Td>{j.current_devices ? `${j.current_devices} device(s)` : '—'}</Td>
                  <Td>{can('operator') && <div className="flex gap-1">
                    <Button size="sm" variant="ghost" onClick={() => setJackEdit(j)}><Pencil className="size-3.5" /></Button>
                    <Button size="sm" variant="ghost" onClick={async () => { await api.del(`/api/jacks/${j.id}`); qc.invalidateQueries({ queryKey: ['jacks'] }) }}><Trash2 className="size-3.5 text-red-600" /></Button>
                  </div>}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <div className="grid gap-5 md:grid-cols-2">
        <Card title="Racks" actions={can('operator') && <Button size="sm" onClick={() => setNewRack(true)}><Plus className="size-3.5" /></Button>}>
          {myRacks.length ? <ul className="space-y-1 text-sm">{myRacks.map((r) => <li key={r.id} className="flex justify-between"><span>{r.name}</span><span className="text-slate-400">{r.units}U</span></li>)}</ul> : <div className="text-sm text-slate-400">No racks</div>}
        </Card>
        <Card title="Patch panels" actions={can('operator') && <Button size="sm" onClick={() => setNewPanel(true)}><Plus className="size-3.5" /></Button>}>
          {myPanels.length ? <ul className="space-y-1 text-sm">{myPanels.map((p) => <li key={p.id} className="flex justify-between"><span>{p.name}</span><span className="text-slate-400">{p.port_count} ports</span></li>)}</ul> : <div className="text-sm text-slate-400">No patch panels</div>}
        </Card>
      </div>
      <Card title="Devices here" padded={false}>
        {devices.isLoading ? <Loading /> : devices.data?.devices.length ? <DeviceTable rows={devices.data.devices} /> : <Empty title="No devices placed here">Set a device's location on its page, or assign switches here — devices behind a switch inherit its location.</Empty>}
      </Card>
      <JackForm value={jackEdit} all={all} panels={panels.data ?? []} onClose={() => setJackEdit(null)} />
      <SimpleCreate open={newRack} title="New rack" onClose={() => setNewRack(false)} fields={[['name', 'Name'], ['units', 'Units (U)']]}
        onSubmit={async (v) => { await api.post('/api/racks', { location_id: loc.id, name: v.name, units: Number(v.units || 42) }); qc.invalidateQueries({ queryKey: ['racks'] }) }} />
      <SimpleCreate open={newPanel} title="New patch panel" onClose={() => setNewPanel(false)} fields={[['name', 'Name'], ['ports', 'Ports']]}
        onSubmit={async (v) => { await api.post('/api/patch-panels', { location_id: loc.id, name: v.name, port_count: Number(v.ports || 24) }); qc.invalidateQueries({ queryKey: ['patch-panels'] }) }} />
    </div>
  )
}

function SimpleCreate({ open, title, fields, onClose, onSubmit }: { open: boolean; title: string; fields: [string, string][]; onClose: () => void; onSubmit: (v: Record<string, string>) => Promise<void> }) {
  const [v, setV] = useState<Record<string, string>>({})
  const [err, setErr] = useState<unknown>(null)
  return (
    <Modal open={open} onClose={onClose} title={title} footer={<>
      <Button variant="ghost" onClick={onClose}>Cancel</Button>
      <Button variant="primary" onClick={async () => { try { await onSubmit(v); setV({}); onClose() } catch (e) { setErr(e) } }}>Create</Button>
    </>}>
      <div className="space-y-3">
        {fields.map(([k, label]) => <Field key={k} label={label}><Input value={v[k] ?? ''} onChange={(e) => setV({ ...v, [k]: e.target.value })} /></Field>)}
      </div>
      <ErrorBox error={err} />
    </Modal>
  )
}

function JackForm({ value, all, panels, onClose }: { value: Partial<Jack> | null; all: Location[]; panels: PatchPanel[]; onClose: () => void }) {
  const [v, setV] = useState<Partial<Jack>>({})
  const [err, setErr] = useState<unknown>(null)
  const qc = useQueryClient()
  const open = !!value
  useEffect(() => {
    if (value) setV({ ...value })
  }, [value])
  const switches = useQuery({ queryKey: ['devices', 'switches'], queryFn: () => api.get<{ devices: DeviceRow[] }>('/api/devices?managed=true&limit=1000'), enabled: open })
  const ifaces = useQuery({ queryKey: ['interfaces', v.switch_device_id], queryFn: () => api.get<Interface[]>(`/api/devices/${v.switch_device_id}/interfaces`), enabled: open && !!v.switch_device_id })
  const close = () => { setV({}); setErr(null); onClose() }
  return (
    <Modal open={open} onClose={close} title={value?.id ? `Edit jack ${value.label}` : 'New wall jack'} footer={<>
      <Button variant="ghost" onClick={close}>Cancel</Button>
      <Button variant="primary" onClick={async () => {
        try {
          const body = { location_id: v.location_id, label: v.label, patch_panel_id: v.patch_panel_id ?? null, patch_port: v.patch_port ?? null, switch_interface_id: v.switch_interface_id ?? null, description: v.description ?? null }
          if (v.id) await api.put(`/api/jacks/${v.id}`, body)
          else await api.post('/api/jacks', body)
          qc.invalidateQueries({ queryKey: ['jacks'] })
          close()
        } catch (e) { setErr(e) }
      }}>Save</Button>
    </>}>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Label" hint="As printed on the wall, e.g. 214-07"><Input value={v.label ?? ''} onChange={(e) => setV({ ...v, label: e.target.value })} /></Field>
        <Field label="Room">
          <Select value={v.location_id ?? ''} onChange={(e) => setV({ ...v, location_id: Number(e.target.value) })} className="w-full">
            {all.map((l) => <option key={l.id} value={l.id}>{l.path}</option>)}
          </Select>
        </Field>
        <Field label="Patch panel">
          <Select value={v.patch_panel_id ?? ''} onChange={(e) => setV({ ...v, patch_panel_id: e.target.value ? Number(e.target.value) : null })} className="w-full">
            <option value="">—</option>
            {panels.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
        </Field>
        <Field label="Patch port"><Input value={v.patch_port ?? ''} onChange={(e) => setV({ ...v, patch_port: e.target.value ? Number(e.target.value) : null })} /></Field>
        <Field label="Switch">
          <Select value={v.switch_device_id ?? ''} onChange={(e) => setV({ ...v, switch_device_id: e.target.value ? Number(e.target.value) : null, switch_interface_id: null })} className="w-full">
            <option value="">—</option>
            {switches.data?.devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </Select>
        </Field>
        <Field label="Switch port">
          <Select value={v.switch_interface_id ?? ''} onChange={(e) => setV({ ...v, switch_interface_id: e.target.value ? Number(e.target.value) : null })} className="w-full" disabled={!v.switch_device_id}>
            <option value="">—</option>
            {ifaces.data?.filter((i) => i.if_type === 6).map((i) => <option key={i.id} value={i.id}>{i.name}{i.attached ? ` (${i.attached} device)` : ''}</option>)}
          </Select>
        </Field>
      </div>
      <ErrorBox error={err} />
    </Modal>
  )
}
