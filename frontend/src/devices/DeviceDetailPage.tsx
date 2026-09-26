import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Share2, TerminalSquare } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '@/api/client'
import type { Credential, DeviceDetail, DeviceRow, Evidence, Interface, Location, NetEvent } from '@/api/types'
import { DeviceIcon } from '@/components/DeviceIcon'
import { Badge, Button, Card, Confidence, Empty, ErrorBox, Field, Input, KV, Loading, Select, StatusDot, Table, Tabs, Td, Textarea, Th } from '@/components/ui'
import { ago, bps, dateTime, DEVICE_TYPES, SOURCE_LABELS, speed, typeLabel, uptime } from '@/lib/format'
import { useAuth } from '@/lib/auth'
import { TerminalDrawer } from '@/terminal/TerminalDrawer'
import { sevTone } from '@/pages/Dashboard'
import { DeviceTable } from './DeviceTable'

type Tab = 'overview' | 'interfaces' | 'neighbors' | 'endpoints' | 'context' | 'history' | 'advanced'

export default function DeviceDetailPage() {
  const { id } = useParams()
  const devId = Number(id)
  const [tab, setTab] = useState<Tab>('overview')
  const [cli, setCli] = useState<'ssh' | 'telnet' | null>(null)
  const { can } = useAuth()
  const navigate = useNavigate()
  const q = useQuery({ queryKey: ['device', devId], queryFn: () => api.get<DeviceDetail>(`/api/devices/${devId}`) })
  useEffect(() => setTab('overview'), [devId])
  if (q.isLoading) return <Loading />
  if (q.error || !q.data) return <div className="p-6"><ErrorBox error={q.error ?? 'Not found'} /></div>
  const d = q.data
  const isSwitch = d.managed || d.stats.endpoints > 0
  const tabs: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    ...(d.managed ? [{ id: 'interfaces' as Tab, label: `Interfaces (${d.stats.interfaces})` }, { id: 'neighbors' as Tab, label: `Neighbors (${d.stats.neighbors})` }] : []),
    ...(isSwitch ? [{ id: 'endpoints' as Tab, label: `Connected devices (${d.stats.endpoints})` }] : []),
    { id: 'context', label: 'Location & notes' },
    { id: 'history', label: 'History' },
    { id: 'advanced', label: 'Advanced details' },
  ]
  return (
    <div className="p-6">
      <button onClick={() => navigate(-1)} className="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800">
        <ArrowLeft className="size-4" /> Back
      </button>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="grid size-12 place-items-center rounded-xl bg-white shadow-sm ring-1 ring-slate-200">
            <DeviceIcon type={d.device_type} className="size-6" />
          </div>
          <div>
            <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-900">
              <StatusDot status={d.status} /> {d.name}
            </h1>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-500">
              <span>{typeLabel(d.device_type)}</span>
              {!d.type_overridden && <Confidence value={d.device_type_confidence} />}
              {d.vendor && <span>· {d.vendor}</span>}
              {d.model && <span>{d.model}</span>}
              {d.ip && <span className="font-mono">· {d.ip}</span>}
              {d.managed ? <Badge tone="brand">Managed via SNMP</Badge> : <Badge>{SOURCE_LABELS[d.discovered_via] ?? d.discovered_via}</Badge>}
              {d.tags.map((t) => <Badge key={t} tone="violet">{t}</Badge>)}
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          <Link to={`/topology?focus=${d.id}`}>
            <Button><Share2 className="size-4" /> Show in topology</Button>
          </Link>
          {can('operator') && d.access.ssh_credential_id && (
            <Button variant="primary" onClick={() => setCli('ssh')}><TerminalSquare className="size-4" /> Open CLI</Button>
          )}
          {can('operator') && d.access.telnet_enabled && d.access.telnet_allowed && (
            <Button onClick={() => setCli('telnet')}><TerminalSquare className="size-4" /> Telnet</Button>
          )}
        </div>
      </div>
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <div className="mt-5">
        {tab === 'overview' && <Overview d={d} />}
        {tab === 'interfaces' && <Interfaces id={d.id} />}
        {tab === 'neighbors' && <Neighbors id={d.id} />}
        {tab === 'endpoints' && <Endpoints id={d.id} />}
        {tab === 'context' && <ContextTab d={d} />}
        {tab === 'history' && <History d={d} />}
        {tab === 'advanced' && <Advanced d={d} />}
      </div>
      {cli && <TerminalDrawer deviceId={d.id} deviceName={d.name} protocol={cli} onClose={() => setCli(null)} />}
    </div>
  )
}

function EvidenceList({ title, value, confidence, items }: { title: string; value: string | null; confidence?: number; items?: Evidence[] }) {
  return (
    <div className="rounded-lg border border-slate-200 p-3">
      <div className="flex items-center justify-between">
        <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{title}</div>
        <Confidence value={confidence} />
      </div>
      <div className="mt-1 text-base font-semibold text-slate-900">{value || <span className="text-slate-400">Not determined</span>}</div>
      {items && items.length > 0 ? (
        <ul className="mt-2 space-y-1">
          {items.map((e, i) => (
            <li key={i} className="flex gap-2 text-xs">
              <span className="w-24 shrink-0 font-medium text-slate-600">{e.source}</span>
              <span className="text-slate-500">
                {e.detail}
                {e.value !== value && <span className="text-slate-400"> ({e.value})</span>}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="mt-2 text-xs text-slate-400">No supporting evidence recorded.</div>
      )}
    </div>
  )
}

function Overview({ d }: { d: DeviceDetail }) {
  const f = d.facts ?? {}
  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <div className="space-y-5 lg:col-span-2">
        <Card title="Why Nexus thinks this is…">
          <div className="grid gap-3 md:grid-cols-3">
            <EvidenceList title="Device type" value={d.type_overridden ? `${typeLabel(d.device_type)} (set by you)` : typeLabel(d.device_type)} confidence={d.type_overridden ? undefined : d.device_type_confidence} items={d.evidence.device_type} />
            <EvidenceList title="Operating system" value={d.os_name} confidence={d.os_confidence} items={d.evidence.os} />
            <EvidenceList title="Vendor" value={d.vendor} confidence={f.vendor_confidence} items={d.evidence.vendor} />
          </div>
          {d.evidence.identity && (
            <div className="mt-3 text-xs text-slate-500">
              {d.evidence.identity.map((e, i) => <div key={i}>{e.detail}</div>)}
            </div>
          )}
        </Card>
        {d.managed && (
          <Card title="Device">
            <KV items={[
              ['Model', d.model],
              ['Serial', f.serial],
              ['Software', f.os_version],
              ['Uptime', uptime(f.uptime_seconds)],
              ['CPU', f.cpu_percent != null ? `${f.cpu_percent}%` : '—'],
              ['Spanning tree root', f.stp_root],
              ['Memory', f.memory_percent != null ? `${f.memory_percent}%` : '—'],
              ['SNMP location', f.sys_location],
              ['Contact', f.sys_contact],
              ['Last polled', ago(f.last_polled_at)],
            ]} />
          </Card>
        )}
        {d.sensors.length > 0 && (
          <Card title="Sensors" padded={false}>
            <Table>
              <thead><tr><Th>Sensor</Th><Th>Value</Th><Th>Status</Th></tr></thead>
              <tbody>
                {d.sensors.map((s, i) => (
                  <tr key={i}>
                    <Td>{s.name} <span className="text-xs text-slate-400">{s.kind}</span></Td>
                    <Td>{s.value != null ? `${s.value} ${s.unit ?? ''}` : '—'}</Td>
                    <Td><Badge tone={s.status === 'ok' ? 'green' : s.status === 'critical' ? 'red' : s.status === 'warning' ? 'amber' : 'slate'}>{s.status ?? 'unknown'}</Badge></Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>
        )}
      </div>
      <div className="space-y-5">
        <Card title="Where is it?">
          <KV items={[
            ['Switch', d.switch_id ? <Link className="hover:underline" to={`/devices/${d.switch_id}`}>{d.switch_name}</Link> : null],
            ['Port', d.switch_port],
            ['VLAN', d.vlan],
            ['Wall jack', d.jack],
            ['Location', d.location_path ? <>{d.location_path}{d.location_source !== 'user' && <span className="text-slate-400"> (inferred from {d.location_source})</span>}</> : null],
            ['Port certainty', d.attachment_confidence != null ? <Confidence value={d.attachment_confidence} /> : null],
          ]} />
        </Card>
        <Card title="Identity">
          <div className="space-y-3 text-sm">
            <div>
              <div className="mb-1 text-xs font-medium text-slate-500">IP addresses</div>
              {d.addresses.map((a) => <div key={a.ip} className="font-mono text-xs">{a.ip}{a.prefix_len && a.prefix_len < 32 ? `/${a.prefix_len}` : ''} <span className="text-slate-400">{a.source}</span></div>)}
              {!d.addresses.length && <div className="text-xs text-slate-400">—</div>}
            </div>
            <div>
              <div className="mb-1 text-xs font-medium text-slate-500">MAC addresses</div>
              {d.macs.slice(0, 8).map((m) => <div key={m.mac} className="font-mono text-xs">{m.mac} <span className="text-slate-400">{m.source}</span></div>)}
              {d.macs.length > 8 && <div className="text-xs text-slate-400">+{d.macs.length - 8} more</div>}
              {f.random_mac && <div className="mt-1 text-xs text-amber-600">Randomized (private) MAC address</div>}
            </div>
            <div>
              <div className="mb-1 text-xs font-medium text-slate-500">Names</div>
              {d.hostnames.map((h) => <div key={h.name + h.source} className="text-xs">{h.name} <span className="text-slate-400">{h.source}</span></div>)}
              {!d.hostnames.length && <div className="text-xs text-slate-400">—</div>}
            </div>
            <div className="text-xs text-slate-500">First seen {dateTime(d.first_seen)} · last seen {ago(d.last_seen)}</div>
          </div>
        </Card>
      </div>
    </div>
  )
}

function Interfaces({ id }: { id: number }) {
  const q = useQuery({ queryKey: ['interfaces', id], queryFn: () => api.get<Interface[]>(`/api/devices/${id}/interfaces`) })
  const [onlyUp, setOnlyUp] = useState(false)
  if (q.isLoading) return <Loading />
  const rows = (q.data ?? []).filter((i) => !onlyUp || i.oper_status === 'up')
  return (
    <Card padded={false} title={`${rows.length} interfaces`} actions={
      <label className="flex items-center gap-1.5 text-xs text-slate-600"><input type="checkbox" checked={onlyUp} onChange={(e) => setOnlyUp(e.target.checked)} /> Only up</label>
    }>
      <Table>
        <thead>
          <tr><Th>Port</Th><Th>Status</Th><Th>Speed</Th><Th>Medium</Th><Th>VLAN</Th><Th>Connected to</Th><Th>Traffic in / out</Th><Th>Optics</Th></tr>
        </thead>
        <tbody>
          {rows.map((i) => (
            <tr key={i.id} className="hover:bg-slate-50/70">
              <Td>
                <div className="font-medium">{i.name}</div>
                {i.alias && <div className="text-xs text-slate-500">{i.alias}</div>}
                {i.jack && <Badge tone="violet">Jack {i.jack}</Badge>}
              </Td>
              <Td>
                <span className="inline-flex items-center gap-1.5"><StatusDot status={i.oper_status === 'up' ? 'up' : i.admin_status === 'down' ? 'unknown' : 'down'} />{i.admin_status === 'down' ? 'disabled' : i.oper_status}</span>
                {i.duplex && i.duplex !== 'unknown' && <div className="text-xs text-slate-400">{i.duplex} duplex</div>}
                {i.stp_state && i.stp_state !== 'forwarding' && i.stp_state !== 'disabled' && <Badge tone="amber" title="Spanning tree state">STP {i.stp_state}</Badge>}
              </Td>
              <Td>{i.oper_status === 'up' ? speed(i.speed_bps) : '—'}</Td>
              <Td>{i.medium && i.medium !== 'unknown' ? <Badge tone={i.medium === 'fiber' ? 'blue' : 'slate'}>{i.medium}</Badge> : <span className="text-slate-400">—</span>}</Td>
              <Td className="text-xs">{i.pvid ? `${i.pvid}` : ''}{i.vlans.length > 1 ? <div className="text-slate-400">trunk: {i.vlans.slice(0, 6).join(', ')}{i.vlans.length > 6 ? '…' : ''}</div> : null}</Td>
              <Td>
                {i.neighbor ? (
                  i.neighbor.device_id ? <Link className="hover:underline" to={`/devices/${i.neighbor.device_id}`}>{i.neighbor.name}</Link> : i.neighbor.name
                ) : i.attached > 0 ? (
                  <span>{i.attached} device{i.attached > 1 ? 's' : ''}</span>
                ) : i.mac_count > 0 ? (
                  <span className="text-slate-500">{i.mac_count} MACs</span>
                ) : null}
                {i.neighbor && <div className="text-xs text-slate-400">{i.neighbor.port} · {i.neighbor.protocol.toUpperCase()}</div>}
                {i.is_uplink && <Badge tone="brand">uplink</Badge>}
              </Td>
              <Td className="whitespace-nowrap text-xs">{i.in_bps != null ? `${bps(i.in_bps)} / ${bps(i.out_bps)}` : '—'}
                {i.in_bps != null && i.speed_bps ? <div className="text-slate-400">{utilization(i)}% used</div> : null}{(i.in_errors ?? 0) > 0 && <div className="text-amber-600">{i.in_errors} input errors</div>}</Td>
              <Td className="text-xs">
                {i.optic ? (
                  <>
                    <div>{i.optic.type ?? i.optic.part_number}</div>
                    {i.optic.rx_dbm != null && <div className={i.optic.rx_dbm < -14 ? 'text-red-600' : 'text-slate-500'}>Rx {i.optic.rx_dbm} dBm · Tx {i.optic.tx_dbm} dBm</div>}
                    <div className="text-slate-400">{i.optic.vendor} {i.optic.serial}</div>
                  </>
                ) : null}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  )
}

function utilization(i: Interface): string {
  const peak = Math.max(i.in_bps ?? 0, i.out_bps ?? 0)
  const pct = i.speed_bps ? (peak / i.speed_bps) * 100 : 0
  return pct < 0.1 && pct > 0 ? '<0.1' : pct.toFixed(pct < 10 ? 1 : 0)
}

function Neighbors({ id }: { id: number }) {
  const q = useQuery({ queryKey: ['neighbors', id], queryFn: () => api.get<Record<string, any>[]>(`/api/devices/${id}/neighbors`) })
  if (q.isLoading) return <Loading />
  if (!q.data?.length) return <Card><Empty title="No LLDP/CDP neighbors">This device does not report any neighbors, or LLDP/CDP is disabled.</Empty></Card>
  return (
    <Card padded={false}>
      <Table>
        <thead><tr><Th>Local port</Th><Th>Neighbor</Th><Th>Remote port</Th><Th>Management IP</Th><Th>Capabilities</Th><Th>Protocol</Th></tr></thead>
        <tbody>
          {q.data.map((n) => (
            <tr key={n.id}>
              <Td className="font-medium">{n.local_port}</Td>
              <Td>{n.remote_device_id ? <Link to={`/devices/${n.remote_device_id}`} className="hover:underline">{n.remote_sys_name ?? n.remote_chassis_id}</Link> : n.remote_sys_name ?? n.remote_chassis_id}
                <div className="max-w-sm truncate text-xs text-slate-400" title={n.remote_sys_descr}>{n.remote_platform ?? n.remote_sys_descr}</div>
              </Td>
              <Td>{n.remote_port_id}<div className="text-xs text-slate-400">{n.remote_port_descr}</div></Td>
              <Td className="font-mono text-xs">{n.remote_mgmt_ip ?? '—'}</Td>
              <Td>{(n.remote_capabilities as string[]).map((c) => <Badge key={c} className="mr-1">{c}</Badge>)}</Td>
              <Td><Badge>{String(n.protocol).toUpperCase()}</Badge></Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  )
}

function Endpoints({ id }: { id: number }) {
  const q = useQuery({ queryKey: ['endpoints', id], queryFn: () => api.get<DeviceRow[]>(`/api/devices/${id}/endpoints`) })
  if (q.isLoading) return <Loading />
  if (!q.data?.length) return <Card><Empty title="No devices attached">No endpoint was found on this device's access ports.</Empty></Card>
  return <Card padded={false}><DeviceTable rows={q.data} /></Card>
}

function ContextTab({ d }: { d: DeviceDetail }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [c, setC] = useState({ ...d.context, tagsText: d.context.tags.join(', ') })
  const [saved, setSaved] = useState(false)
  const [err, setErr] = useState<unknown>(null)
  const locs = useQuery({ queryKey: ['locations'], queryFn: () => api.get<Location[]>('/api/locations') })
  const creds = useQuery({ queryKey: ['credentials'], queryFn: () => api.get<Credential[]>('/api/credentials'), enabled: can('operator') })
  const [access, setAccess] = useState(d.access)
  const editable = can('operator')
  const save = async () => {
    setErr(null)
    try {
      await api.put(`/api/devices/${d.id}/context`, {
        display_name: c.display_name, description: c.description, department: c.department,
        device_type_override: c.device_type_override || null, location_id: c.location_id, rack_id: c.rack_id, rack_unit: c.rack_unit,
        tags: c.tagsText.split(',').map((t) => t.trim()).filter(Boolean),
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
      qc.invalidateQueries({ queryKey: ['device', d.id] })
      qc.invalidateQueries({ queryKey: ['devices'] })
    } catch (e) {
      setErr(e)
    }
  }
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Your context" actions={editable && <Button variant="primary" size="sm" onClick={save}>{saved ? 'Saved' : 'Save'}</Button>}>
        <p className="mb-3 text-xs text-slate-500">This information is yours. It is stored separately and never overwrites what Nexus discovered.</p>
        <fieldset disabled={!editable} className="space-y-3">
          <Field label="Display name" hint={`Discovered name: ${d.hostname ?? d.facts?.sys_name ?? '—'}`}>
            <Input value={c.display_name ?? ''} onChange={(e) => setC({ ...c, display_name: e.target.value })} />
          </Field>
          <Field label="Location">
            <Select value={c.location_id ?? ''} onChange={(e) => setC({ ...c, location_id: e.target.value ? Number(e.target.value) : null })} className="w-full">
              <option value="">— Not set{d.location_path ? ` (currently inferred: ${d.location_path})` : ''} —</option>
              {locs.data?.map((l) => <option key={l.id} value={l.id}>{l.path}</option>)}
            </Select>
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Department"><Input value={c.department ?? ''} onChange={(e) => setC({ ...c, department: e.target.value })} /></Field>
            <Field label="Device type override" hint="Only if the automatic classification is wrong">
              <Select value={c.device_type_override ?? ''} onChange={(e) => setC({ ...c, device_type_override: e.target.value || null })} className="w-full">
                <option value="">Automatic ({typeLabel(d.type_overridden ? 'unknown' : d.device_type)})</option>
                {DEVICE_TYPES.map((t) => <option key={t} value={t}>{typeLabel(t)}</option>)}
              </Select>
            </Field>
          </div>
          <Field label="Tags" hint="Comma separated"><Input value={c.tagsText} onChange={(e) => setC({ ...c, tagsText: e.target.value })} placeholder="critical, lab, legacy" /></Field>
          <Field label="Description"><Textarea rows={3} value={c.description ?? ''} onChange={(e) => setC({ ...c, description: e.target.value })} /></Field>
        </fieldset>
        <ErrorBox error={err} />
      </Card>
      {d.managed && editable && (
        <Card title="CLI access" actions={<Button size="sm" onClick={async () => {
          try {
            await api.put(`/api/devices/${d.id}/access`, { ssh_credential_id: access.ssh_credential_id, telnet_credential_id: access.telnet_credential_id, telnet_enabled: access.telnet_enabled })
            qc.invalidateQueries({ queryKey: ['device', d.id] })
          } catch (e) { setErr(e) }
        }}>Save</Button>}>
          <div className="space-y-3">
            <Field label="SSH credential">
              <Select value={access.ssh_credential_id ?? ''} onChange={(e) => setAccess({ ...access, ssh_credential_id: e.target.value ? Number(e.target.value) : null })} className="w-full">
                <option value="">— none —</option>
                {creds.data?.filter((x) => x.kind === 'ssh').map((x) => <option key={x.id} value={x.id}>{x.name} ({x.summary.username})</option>)}
              </Select>
            </Field>
            <Field label="Telnet credential">
              <Select value={access.telnet_credential_id ?? ''} onChange={(e) => setAccess({ ...access, telnet_credential_id: e.target.value ? Number(e.target.value) : null })} className="w-full">
                <option value="">— none —</option>
                {creds.data?.filter((x) => x.kind === 'telnet').map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
              </Select>
            </Field>
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" disabled={!can('admin')} checked={access.telnet_enabled} onChange={(e) => setAccess({ ...access, telnet_enabled: e.target.checked })} className="mt-1" />
              <span>Allow Telnet for this device <span className="block text-xs text-amber-700">Telnet sends passwords unencrypted. Admins only; must also be allowed in Settings.</span></span>
            </label>
            {access.ssh_host_key && <div className="text-xs text-slate-500">Pinned SSH host key: <span className="font-mono">{access.ssh_host_key}</span></div>}
            <p className="text-xs text-slate-500">Credentials are managed in Settings → Credentials. They are never sent to your browser.</p>
          </div>
        </Card>
      )}
    </div>
  )
}

function History({ d }: { d: DeviceDetail }) {
  const ev = useQuery({ queryKey: ['device-events', d.id], queryFn: () => api.get<NetEvent[]>(`/api/devices/${d.id}/events`) })
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Switch port history" padded={false}>
        {d.attachment_history.length ? (
          <Table>
            <thead><tr><Th>Switch / port</Th><Th>VLAN</Th><Th>From</Th><Th>Until</Th></tr></thead>
            <tbody>
              {d.attachment_history.map((a) => (
                <tr key={a.id}>
                  <Td><Link to={`/devices/${a.switch_id}`} className="hover:underline">{a.switch}</Link> <span className="text-slate-500">{a.port}</span></Td>
                  <Td>{a.vlan ?? '—'}</Td>
                  <Td className="text-xs">{dateTime(a.started_at)}</Td>
                  <Td className="text-xs">{a.ended_at ? dateTime(a.ended_at) : <Badge tone="green">current</Badge>}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : <Empty title="No port history" />}
      </Card>
      <Card title="Events" padded={false}>
        <ul className="divide-y divide-slate-100">
          {ev.data?.map((e) => (
            <li key={e.id} className="flex items-center gap-2 px-4 py-2 text-sm">
              <Badge tone={sevTone(e.severity)}>{e.severity}</Badge>
              <span className="flex-1">{e.message}</span>
              <span className="text-xs text-slate-400">{ago(e.ts)}</span>
            </li>
          ))}
          {!ev.data?.length && <li className="px-4 py-6 text-center text-sm text-slate-400">No events</li>}
        </ul>
      </Card>
    </div>
  )
}

function Advanced({ d }: { d: DeviceDetail }) {
  const [table, setTable] = useState<'fdb' | 'arp' | 'routes' | 'vlans' | null>(null)
  const t = useQuery({ queryKey: ['table', d.id, table], queryFn: () => api.get<Record<string, any>[]>(`/api/devices/${d.id}/tables/${table}`), enabled: !!table })
  const f = d.facts ?? {}
  return (
    <div className="space-y-5">
      <Card title="Technical details">
        <KV items={[
          ['sysDescr', <pre className="whitespace-pre-wrap font-mono text-xs">{f.sys_descr}</pre>],
          ['sysObjectID', <span className="font-mono text-xs">{f.sys_object_id}</span>],
          ['Chassis ID', <span className="font-mono text-xs">{f.chassis_id}</span>],
          ['Hardware revision', f.hardware_rev],
          ['Capabilities', [f.is_router && 'IP forwarding', f.is_bridge && 'bridging', f.is_printer && 'printer MIB'].filter(Boolean).join(', ') || '—'],
          ['OUI vendor', f.oui_vendor],
          ['Discovered via', SOURCE_LABELS[f.discovered_via] ?? f.discovered_via],
          ['Last full discovery', dateTime(f.last_discovered_at)],
          ['Fingerprinted', dateTime(f.fingerprinted_at)],
        ]} />
      </Card>
      {d.managed && (
        <Card title="Raw tables" actions={
          <div className="flex gap-1">
            {(['fdb', 'arp', 'routes', 'vlans'] as const).map((x) => (
              <Button key={x} size="sm" variant={table === x ? 'primary' : 'secondary'} onClick={() => setTable(x)}>
                {x === 'fdb' ? `MAC table (${d.stats.fdb})` : x === 'arp' ? `ARP (${d.stats.arp})` : x === 'routes' ? `Routes (${d.stats.routes})` : `VLANs (${d.stats.vlans})`}
              </Button>
            ))}
          </div>
        } padded={false}>
          {!table ? <div className="p-4 text-sm text-slate-500">Choose a table to inspect the raw data collected from the device.</div> : t.isLoading ? <Loading /> : <RawTable rows={t.data ?? []} />}
        </Card>
      )}
      {d.inventory.length > 0 && (
        <Card title="Hardware inventory (ENTITY-MIB)" padded={false}>
          <RawTable rows={d.inventory.map(({ ent_index, parent_index, ...rest }) => rest)} />
        </Card>
      )}
      {Object.keys(d.fingerprint ?? {}).length > 1 && (
        <Card title="Endpoint fingerprint">
          <pre className="overflow-x-auto rounded-lg bg-slate-50 p-3 font-mono text-xs">{JSON.stringify(d.fingerprint, null, 2)}</pre>
        </Card>
      )}
    </div>
  )
}

function RawTable({ rows }: { rows: Record<string, any>[] }) {
  if (!rows.length) return <div className="p-4 text-sm text-slate-400">No rows</div>
  const cols = Object.keys(rows[0])
  return (
    <div className="max-h-[60vh] overflow-auto">
      <Table>
        <thead><tr>{cols.map((c) => <Th key={c}>{c.replace(/_/g, ' ')}</Th>)}</tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {cols.map((c) => (
                <Td key={c} className="font-mono text-xs">
                  {c === 'device' && r.device_id ? <Link className="hover:underline" to={`/devices/${r.device_id}`}>{r[c]}</Link> : typeof r[c] === 'object' && r[c] !== null ? JSON.stringify(r[c]) : String(r[c] ?? '')}
                </Td>
              ))}
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  )
}
