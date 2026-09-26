import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ExternalLink, Link2, RotateCcw, Search, X } from 'lucide-react'
import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, qs } from '@/api/client'
import type { Location, TopoEdge, TopoNode } from '@/api/types'
import { DeviceIcon, TYPE_COLORS } from '@/components/DeviceIcon'
import { Badge, Button, cn, ErrorBox, Field, Input, Loading, Modal, Select } from '@/components/ui'
import { typeLabel } from '@/lib/format'
import { useAuth } from '@/lib/auth'

type DevNodeData = TopoNode & { highlight?: boolean; dim?: boolean } & Record<string, unknown>

const DeviceNode = memo(function DeviceNode({ data, selected }: NodeProps<Node<DevNodeData>>) {
  const d = data
  return (
    <div
      className={cn(
        'rounded-xl border bg-white px-2.5 py-1.5 shadow-sm transition-all',
        d.infra ? 'min-w-[150px]' : 'min-w-[110px]',
        selected ? 'border-brand-500 ring-2 ring-brand-500/30' : d.highlight ? 'border-amber-400 ring-2 ring-amber-300' : 'border-slate-200',
        d.dim && 'opacity-30',
      )}
    >
      <Handle type="target" position={Position.Top} className="!size-1.5 !border-0 !bg-slate-300" />
      <div className="flex items-center gap-1.5">
        <DeviceIcon type={d.type} className={d.infra ? 'size-5' : 'size-4'} />
        <div className="min-w-0">
          <div className={cn('truncate font-semibold text-slate-800', d.infra ? 'max-w-[150px] text-xs' : 'max-w-[110px] text-[11px]')}>{d.label}</div>
          <div className="truncate font-mono text-[10px] text-slate-400">{d.ip ?? typeLabel(d.type)}</div>
        </div>
        <span className={cn('ml-auto size-2 shrink-0 rounded-full', d.status === 'up' ? 'bg-emerald-500' : d.status === 'down' ? 'bg-red-500' : 'bg-slate-300')} />
      </div>
      <Handle type="source" position={Position.Bottom} className="!size-1.5 !border-0 !bg-slate-300" />
    </div>
  )
})

const GroupNode = memo(function GroupNode({ data }: NodeProps<Node<{ label: string }>>) {
  return (
    <div className="h-full w-full rounded-2xl border-2 border-dashed border-slate-300 bg-slate-100/40">
      <div className="px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{data.label}</div>
    </div>
  )
})

const nodeTypes = { device: DeviceNode, group: GroupNode }

function edgeStyle(e: TopoEdge) {
  const fiber = e.medium === 'fiber'
  return {
    stroke: e.layer === 'l3' ? '#8b5cf6' : fiber ? '#0284c7' : '#94a3b8',
    strokeWidth: e.speed_bps && e.speed_bps >= 10e9 ? 3 : e.speed_bps && e.speed_bps >= 1e9 ? 2 : 1.3,
    strokeDasharray: e.manual ? '6 4' : e.confidence < 0.7 ? '2 3' : undefined,
  }
}

function TopologyInner() {
  const [params, setParams] = useSearchParams()
  const { can } = useAuth()
  const qc = useQueryClient()
  const rf = useReactFlow()
  const [layer, setLayer] = useState(params.get('layer') ?? 'physical')
  const [infraOnly, setInfraOnly] = useState(params.get('infra') === 'true')
  const [locationId, setLocationId] = useState(params.get('location') ?? '')
  const [group, setGroup] = useState(false)
  const [labels, setLabels] = useState(false)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<DevNodeData | null>(null)
  const [linkPick, setLinkPick] = useState<number[]>([])
  const [linkOpen, setLinkOpen] = useState(false)
  const focus = params.get('focus') ?? ''
  const q = useQuery({
    queryKey: ['topology', layer, infraOnly, locationId, focus],
    queryFn: () => api.get<{ nodes: TopoNode[]; edges: TopoEdge[] }>('/api/topology' + qs({ layer, infra_only: infraOnly, location_id: locationId, focus })),
    placeholderData: keepPreviousData,
  })
  const locs = useQuery({ queryKey: ['locations'], queryFn: () => api.get<Location[]>('/api/locations') })
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const pending = useRef<Map<number, { x: number; y: number }>>(new Map())
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => {
    if (!q.data) return
    const term = search.trim().toLowerCase()
    const match = (n: TopoNode) => !!term && (n.label.toLowerCase().includes(term) || (n.ip ?? '').includes(term))
    let rfNodes: Node[] = []
    if (group) {
      const groups = new Map<string, TopoNode[]>()
      for (const n of q.data.nodes) {
        const k = n.floor ? `${n.building ? n.building + ' · ' : ''}${n.floor}` : n.building || n.location || 'Unplaced'
        groups.set(k, [...(groups.get(k) ?? []), n])
      }
      let gx = 0
      for (const [label, members] of [...groups.entries()].sort()) {
        const cols = Math.max(1, Math.ceil(Math.sqrt(members.length)))
        const w = cols * 180 + 40
        const rows = Math.ceil(members.length / cols)
        const h = rows * 90 + 60
        const gid = `g-${label}`
        rfNodes.push({ id: gid, type: 'group', position: { x: gx, y: 0 }, data: { label }, style: { width: w, height: h }, draggable: false, selectable: false })
        members
          .sort((a, b) => a.level - b.level || a.label.localeCompare(b.label))
          .forEach((n, i) => {
            rfNodes.push({ id: String(n.id), type: 'device', parentId: gid, extent: 'parent', position: { x: 20 + (i % cols) * 180, y: 40 + Math.floor(i / cols) * 90 }, data: { ...n, highlight: match(n), dim: !!term && !match(n) } })
          })
        gx += w + 60
      }
    } else {
      rfNodes = q.data.nodes.map((n) => ({
        id: String(n.id),
        type: 'device',
        position: { x: n.x ?? 0, y: n.y ?? 0 },
        data: { ...n, highlight: match(n), dim: !!term && !match(n) },
      }))
    }
    setNodes(rfNodes)
    setEdges(
      q.data.edges.map((e) => ({
        id: e.id,
        source: String(e.a),
        target: String(e.b),
        type: 'default',
        style: edgeStyle(e),
        label: labels ? `${e.a_port ?? ''} ↔ ${e.b_port ?? ''}` : undefined,
        labelStyle: { fontSize: 9, fill: '#475569' },
        labelBgStyle: { fill: '#fff', fillOpacity: 0.85 },
        markerEnd: undefined,
        data: { ...e } as Record<string, unknown>,
        animated: false,
      })),
    )
  }, [q.data, group, labels, search, setNodes, setEdges])

  useEffect(() => {
    if (q.data) window.setTimeout(() => rf.fitView({ duration: 300 }), 50)
  }, [q.data, group, rf])

  useEffect(() => {
    if (!search.trim() || !q.data) return
    const term = search.trim().toLowerCase()
    const hit = q.data.nodes.find((n) => n.label.toLowerCase().includes(term) || (n.ip ?? '').includes(term))
    if (hit && !group) rf.setCenter((hit.x ?? 0) + 70, (hit.y ?? 0) + 20, { zoom: 1.2, duration: 400 })
  }, [search, q.data, rf, group])

  const onNodeDragStop = useCallback(
    (_: unknown, node: Node) => {
      if (group || !can('operator') || node.type !== 'device') return
      pending.current.set(Number(node.id), node.position)
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(async () => {
        const positions = [...pending.current.entries()].map(([id, p]) => ({ id, x: p.x, y: p.y }))
        pending.current.clear()
        await api.put('/api/topology/layout', { positions }).catch(() => undefined)
      }, 600)
    },
    [group, can],
  )

  const floors = useMemo(() => (locs.data ?? []).filter((l) => l.kind !== 'room' && l.kind !== 'closet'), [locs.data])

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 bg-white px-4 py-2.5">
        <h1 className="mr-2 text-base font-semibold text-slate-900">Topology</h1>
        <Select value={layer} onChange={(e) => setLayer(e.target.value)}>
          <option value="physical">Physical / L2</option>
          <option value="l3">L3 (routing)</option>
          <option value="">All layers</option>
        </Select>
        <Select value={locationId} onChange={(e) => { setLocationId(e.target.value); setParams((p) => { e.target.value ? p.set('location', e.target.value) : p.delete('location'); return p }) }}>
          <option value="">All locations</option>
          {floors.map((l) => <option key={l.id} value={l.id}>{l.path}</option>)}
        </Select>
        <label className="flex items-center gap-1.5 text-sm text-slate-600"><input type="checkbox" checked={infraOnly} onChange={(e) => setInfraOnly(e.target.checked)} /> Network devices only</label>
        <label className="flex items-center gap-1.5 text-sm text-slate-600"><input type="checkbox" checked={group} onChange={(e) => setGroup(e.target.checked)} /> Group by location</label>
        <label className="flex items-center gap-1.5 text-sm text-slate-600"><input type="checkbox" checked={labels} onChange={(e) => setLabels(e.target.checked)} /> Port labels</label>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-slate-400" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Find device" className="h-8 w-44 pl-8" />
        </div>
        {focus && (
          <Button size="sm" onClick={() => setParams((p) => { p.delete('focus'); return p })}>
            <X className="size-3.5" /> Clear focus
          </Button>
        )}
        <div className="flex-1" />
        {can('operator') && (
          <>
            <Button size="sm" disabled={linkPick.length !== 2} onClick={() => setLinkOpen(true)} title="Shift-click two devices, then add a link that discovery cannot see">
              <Link2 className="size-3.5" /> Add link {linkPick.length ? `(${linkPick.length}/2)` : ''}
            </Button>
            <Button size="sm" variant="ghost" onClick={async () => { await api.del('/api/topology/layout'); qc.invalidateQueries({ queryKey: ['topology'] }) }} title="Discard manual positions">
              <RotateCcw className="size-3.5" /> Auto layout
            </Button>
          </>
        )}
      </div>
      <div className="relative min-h-0 flex-1">
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <div className="p-6"><ErrorBox error={q.error} /></div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeDragStop={onNodeDragStop}
            onNodeClick={(ev, n) => {
              if (n.type !== 'device') return
              const data = n.data as unknown as DevNodeData
              if (ev.shiftKey) {
                setLinkPick((p) => (p.includes(data.id) ? p.filter((x) => x !== data.id) : [...p, data.id].slice(-2)))
              } else setSelected(data)
            }}
            onPaneClick={() => setSelected(null)}
            fitView
            minZoom={0.1}
            maxZoom={2.5}
            defaultEdgeOptions={{ markerEnd: { type: MarkerType.Arrow, width: 0, height: 0 } }}
            proOptions={{ hideAttribution: true }}
          >
            <Background gap={24} color="#e2e8f0" />
            <Controls showInteractive={false} />
            <MiniMap pannable zoomable nodeColor={(n) => TYPE_COLORS[(n.data as unknown as DevNodeData)?.type] ?? '#cbd5e1'} />
          </ReactFlow>
        )}
        <Legend />
        {selected && <NodePanel n={selected} onClose={() => setSelected(null)} />}
      </div>
      <ManualLink open={linkOpen} ids={linkPick} nodes={q.data?.nodes ?? []} onClose={() => { setLinkOpen(false); setLinkPick([]) }} />
    </div>
  )
}

function Legend() {
  return (
    <div className="pointer-events-none absolute bottom-3 left-14 flex gap-3 rounded-lg bg-white/90 px-3 py-1.5 text-[11px] text-slate-600 shadow-sm ring-1 ring-slate-200">
      <span className="flex items-center gap-1"><span className="h-0.5 w-5 bg-sky-600" /> fiber</span>
      <span className="flex items-center gap-1"><span className="h-0.5 w-5 bg-slate-400" /> copper / unknown</span>
      <span className="flex items-center gap-1"><span className="h-0.5 w-5 border-t-2 border-dashed border-slate-400" /> manual</span>
      <span className="flex items-center gap-1"><span className="h-0.5 w-5 border-t-2 border-dotted border-slate-400" /> low confidence</span>
      <span>thicker = faster</span>
    </div>
  )
}

function NodePanel({ n, onClose }: { n: DevNodeData; onClose: () => void }) {
  return (
    <div className="absolute right-3 top-3 w-72 animate-fade-in rounded-xl border border-slate-200 bg-white p-4 shadow-lg">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <DeviceIcon type={n.type} className="size-5" />
          <div>
            <div className="font-semibold text-slate-900">{n.label}</div>
            <div className="text-xs text-slate-500">{typeLabel(n.type)}{n.vendor ? ` · ${n.vendor}` : ''}</div>
          </div>
        </div>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-600"><X className="size-4" /></button>
      </div>
      <dl className="mt-3 space-y-1 text-sm">
        {n.ip && <div className="flex justify-between"><dt className="text-slate-500">IP</dt><dd className="font-mono text-xs">{n.ip}</dd></div>}
        {n.model && <div className="flex justify-between"><dt className="text-slate-500">Model</dt><dd>{n.model}</dd></div>}
        {n.location && <div className="flex justify-between gap-2"><dt className="text-slate-500">Location</dt><dd className="text-right text-xs">{n.location}</dd></div>}
        <div className="flex justify-between"><dt className="text-slate-500">Links</dt><dd>{n.degree}</dd></div>
      </dl>
      <div className="mt-3 flex gap-2">
        <Link to={`/devices/${n.id}`} className="flex-1"><Button size="sm" className="w-full"><ExternalLink className="size-3.5" /> Details</Button></Link>
        <Link to={`/topology?focus=${n.id}`} className="flex-1"><Button size="sm" className="w-full">Focus</Button></Link>
      </div>
      {n.tags && n.tags.length > 0 && <div className="mt-2 flex flex-wrap gap-1">{n.tags.map((t) => <Badge key={t} tone="violet">{t}</Badge>)}</div>}
    </div>
  )
}

function ManualLink({ open, ids, nodes, onClose }: { open: boolean; ids: number[]; nodes: TopoNode[]; onClose: () => void }) {
  const [f, setF] = useState({ a_port: '', b_port: '', medium: '', description: '' })
  const [err, setErr] = useState<unknown>(null)
  const qc = useQueryClient()
  const name = (id: number) => nodes.find((n) => n.id === id)?.label ?? `#${id}`
  if (ids.length !== 2) return null
  return (
    <Modal open={open} onClose={onClose} title="Add a physical link" footer={
      <>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" onClick={async () => {
          try {
            await api.post('/api/manual-links', { a_device_id: ids[0], b_device_id: ids[1], ...f })
            qc.invalidateQueries({ queryKey: ['topology'] })
            onClose()
          } catch (e) { setErr(e) }
        }}>Add link</Button>
      </>
    }>
      <p className="mb-3 text-sm text-slate-500">Use this for connections discovery cannot see (e.g. through an unmanaged switch or a media converter). It is shown as a dashed line and kept separate from discovered links.</p>
      <div className="grid grid-cols-2 gap-3">
        <Field label={`${name(ids[0])} port`}><Input value={f.a_port} onChange={(e) => setF({ ...f, a_port: e.target.value })} /></Field>
        <Field label={`${name(ids[1])} port`}><Input value={f.b_port} onChange={(e) => setF({ ...f, b_port: e.target.value })} /></Field>
        <Field label="Medium">
          <Select value={f.medium} onChange={(e) => setF({ ...f, medium: e.target.value })} className="w-full">
            <option value="">Unknown</option><option value="fiber">Fiber</option><option value="copper">Copper</option><option value="wireless">Wireless</option>
          </Select>
        </Field>
        <Field label="Description"><Input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
      </div>
      <ErrorBox error={err} />
    </Modal>
  )
}

export default function TopologyPage() {
  return (
    <ReactFlowProvider>
      <TopologyInner />
    </ReactFlowProvider>
  )
}

