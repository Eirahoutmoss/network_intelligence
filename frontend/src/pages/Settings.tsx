import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, KeyRound, Plus, Trash2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '@/api/client'
import type { Credential, Settings as SettingsT, User } from '@/api/types'
import { Badge, Button, Card, Empty, ErrorBox, Field, Input, Loading, Modal, PageHeader, Select, Table, Tabs, Td, Th } from '@/components/ui'
import { ago, dateTime } from '@/lib/format'
import { useAuth } from '@/lib/auth'

type Tab = 'credentials' | 'discovery' | 'users' | 'audit' | 'cli' | 'account'

export default function Settings() {
  const { can } = useAuth()
  const [tab, setTab] = useState<Tab>(can('operator') ? 'credentials' : 'account')
  const tabs: { id: Tab; label: string }[] = [
    ...(can('operator') ? [{ id: 'credentials' as Tab, label: 'Credentials' }] : []),
    ...(can('admin') ? [{ id: 'discovery' as Tab, label: 'Discovery & security' }, { id: 'users' as Tab, label: 'Users' }, { id: 'audit' as Tab, label: 'Audit log' }, { id: 'cli' as Tab, label: 'CLI sessions' }] : []),
    { id: 'account', label: 'My account' },
  ]
  return (
    <div className="p-6">
      <PageHeader title="Settings" />
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <div className="mt-5">
        {tab === 'credentials' && <Credentials />}
        {tab === 'discovery' && <DiscoverySettings />}
        {tab === 'users' && <Users />}
        {tab === 'audit' && <Audit />}
        {tab === 'cli' && <CLISessions />}
        {tab === 'account' && <Account />}
      </div>
    </div>
  )
}

function Credentials() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['credentials'], queryFn: () => api.get<Credential[]>('/api/credentials') })
  const [open, setOpen] = useState(false)
  return (
    <Card padded={false} title="Stored credentials" actions={can('admin') && <Button size="sm" variant="primary" onClick={() => setOpen(true)}><Plus className="size-3.5" /> Add credential</Button>}>
      <p className="px-4 pt-3 text-xs text-slate-500">Secrets are encrypted with AES-256-GCM using the server master key and are never returned by the API.</p>
      {q.isLoading ? <Loading /> : !q.data?.length ? <Empty icon={<KeyRound className="size-8" />} title="No credentials yet">They are created automatically when you add a device.</Empty> : (
        <Table>
          <thead><tr><Th>Name</Th><Th>Kind</Th><Th>Details</Th><Th>Created</Th><Th /></tr></thead>
          <tbody>
            {q.data.map((c) => (
              <tr key={c.id}>
                <Td className="font-medium">{c.name}</Td>
                <Td><Badge tone={c.kind === 'telnet' ? 'amber' : 'slate'}>{c.kind.toUpperCase()}</Badge></Td>
                <Td className="text-xs text-slate-600">{Object.entries(c.summary).filter(([, v]) => v !== '' && v !== false && v != null).map(([k, v]) => `${k}: ${v}`).join(' · ')}</Td>
                <Td className="text-xs text-slate-500">{dateTime(c.created_at)}</Td>
                <Td>{can('admin') && <Button size="sm" variant="ghost" onClick={async () => {
                  if (!confirm(`Delete credential "${c.name}"? Devices using it will stop being polled until another credential is assigned.`)) return
                  await api.del(`/api/credentials/${c.id}`)
                  qc.invalidateQueries({ queryKey: ['credentials'] })
                }}><Trash2 className="size-3.5 text-red-600" /></Button>}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <NewCredential open={open} onClose={() => setOpen(false)} />
    </Card>
  )
}

function NewCredential({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [kind, setKind] = useState<'snmp' | 'ssh' | 'telnet'>('ssh')
  const [f, setF] = useState<Record<string, string>>({})
  const [err, setErr] = useState<unknown>(null)
  const qc = useQueryClient()
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value })
  return (
    <Modal open={open} onClose={onClose} title="New credential" footer={<>
      <Button variant="ghost" onClick={onClose}>Cancel</Button>
      <Button variant="primary" onClick={async () => {
        try {
          const body = kind === 'snmp'
            ? { kind, name: f.name, snmp: { version: f.version || undefined, community: f.community, username: f.username, password: f.password, auth_protocol: f.auth_protocol || undefined, priv_protocol: f.priv_password ? f.priv_protocol || 'AES' : undefined, priv_password: f.priv_password || undefined, port: f.port ? Number(f.port) : undefined } }
            : { kind, name: f.name, login: { username: f.username, password: f.password, private_key: f.private_key || undefined, port: f.port ? Number(f.port) : undefined } }
          await api.post('/api/credentials', body)
          qc.invalidateQueries({ queryKey: ['credentials'] })
          setF({})
          onClose()
        } catch (e) { setErr(e) }
      }}>Save</Button>
    </>}>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Kind">
          <Select value={kind} onChange={(e) => setKind(e.target.value as typeof kind)} className="w-full">
            <option value="ssh">SSH</option><option value="snmp">SNMP</option><option value="telnet">Telnet</option>
          </Select>
        </Field>
        <Field label="Name"><Input value={f.name ?? ''} onChange={set('name')} placeholder="Core switches" /></Field>
        {kind === 'snmp' && <>
          <Field label="Version"><Select value={f.version ?? ''} onChange={set('version')} className="w-full"><option value="">Automatic</option><option value="3">v3</option><option value="2c">v2c</option></Select></Field>
          <Field label="Community (v2c)"><Input value={f.community ?? ''} onChange={set('community')} /></Field>
          <Field label="Username (v3)"><Input value={f.username ?? ''} onChange={set('username')} /></Field>
          <Field label="Auth password"><Input type="password" value={f.password ?? ''} onChange={set('password')} autoComplete="new-password" /></Field>
          <Field label="Auth protocol"><Select value={f.auth_protocol ?? 'SHA'} onChange={set('auth_protocol')} className="w-full">{['SHA', 'SHA256', 'SHA512', 'MD5'].map((p) => <option key={p}>{p}</option>)}</Select></Field>
          <Field label="Privacy password"><Input type="password" value={f.priv_password ?? ''} onChange={set('priv_password')} autoComplete="new-password" /></Field>
        </>}
        {kind !== 'snmp' && <>
          <Field label="Username"><Input value={f.username ?? ''} onChange={set('username')} autoComplete="off" /></Field>
          <Field label="Password"><Input type="password" value={f.password ?? ''} onChange={set('password')} autoComplete="new-password" /></Field>
          {kind === 'ssh' && <Field label="Private key (optional, PEM)" className="col-span-2"><textarea className="h-24 w-full rounded-lg border border-slate-200 p-2 font-mono text-xs" value={f.private_key ?? ''} onChange={(e) => setF({ ...f, private_key: e.target.value })} /></Field>}
        </>}
        <Field label="Port"><Input value={f.port ?? ''} onChange={set('port')} placeholder={kind === 'snmp' ? '161' : kind === 'ssh' ? '22' : '23'} /></Field>
      </div>
      {kind === 'telnet' && <div className="mt-3 flex items-center gap-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800"><AlertTriangle className="size-4" /> Telnet passwords cross the network in clear text.</div>}
      <ErrorBox error={err} />
    </Modal>
  )
}

function DiscoverySettings() {
  const q = useQuery({ queryKey: ['settings'], queryFn: () => api.get<SettingsT>('/api/settings') })
  const [s, setS] = useState<SettingsT | null>(null)
  const [scope, setScope] = useState('')
  const [saved, setSaved] = useState(false)
  const [err, setErr] = useState<unknown>(null)
  useEffect(() => {
    if (q.data) {
      setS(q.data)
      setScope(q.data.default_scope.join(', '))
    }
  }, [q.data])
  if (!s) return <Loading />
  return (
    <Card title="Discovery defaults & security" actions={<Button size="sm" variant="primary" onClick={async () => {
      try {
        await api.put('/api/settings', { ...s, default_scope: scope.split(/[\s,]+/).filter(Boolean) })
        setSaved(true)
        setTimeout(() => setSaved(false), 2000)
      } catch (e) { setErr(e) }
    }}>{saved ? 'Saved' : 'Save'}</Button>}>
      <div className="grid max-w-2xl gap-4 md:grid-cols-2">
        <Field label="Neighbor hops to follow" hint="How far discovery walks LLDP/CDP neighbors from the seed">
          <Select value={s.default_depth} onChange={(e) => setS({ ...s, default_depth: Number(e.target.value) })} className="w-full">
            {[0, 1, 2, 3, 4, 5, 6].map((d) => <option key={d} value={d}>{d}</option>)}
          </Select>
        </Field>
        <Field label="Maximum devices per discovery"><Input value={s.max_devices} onChange={(e) => setS({ ...s, max_devices: Number(e.target.value) || 0 })} /></Field>
        <Field label="Allowed networks" hint="Empty = the seed's /16. Discovery never leaves these networks." className="md:col-span-2">
          <Input value={scope} onChange={(e) => setScope(e.target.value)} placeholder="10.0.0.0/8, 192.168.10.0/24" />
        </Field>
        <label className="flex items-start gap-2 text-sm md:col-span-2">
          <input type="checkbox" checked={s.active_fingerprinting} onChange={(e) => setS({ ...s, active_fingerprinting: e.target.checked })} className="mt-1" />
          <span>Active endpoint identification by default (NetBIOS, SMB, HTTP banner, service ports)<span className="block text-xs text-slate-500">Rate limited and restricted to the allowed networks. Only enable on networks you are authorized to probe.</span></span>
        </label>
        <label className="flex items-start gap-2 text-sm md:col-span-2">
          <input type="checkbox" checked={s.telnet_allowed} onChange={(e) => setS({ ...s, telnet_allowed: e.target.checked })} className="mt-1" />
          <span>Allow Telnet CLI sessions<span className="block text-xs text-amber-700">Telnet is unencrypted. Devices must also be enabled individually.</span></span>
        </label>
      </div>
      <ErrorBox error={err} />
    </Card>
  )
}

function Users() {
  const qc = useQueryClient()
  const { user } = useAuth()
  const q = useQuery({ queryKey: ['users'], queryFn: () => api.get<User[]>('/api/users') })
  const [f, setF] = useState({ username: '', password: '', role: 'viewer' })
  const [err, setErr] = useState<unknown>(null)
  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
      <Card padded={false} title="Users">
        <Table>
          <thead><tr><Th>User</Th><Th>Role</Th><Th>Last login</Th><Th>Status</Th><Th /></tr></thead>
          <tbody>
            {q.data?.map((u) => (
              <tr key={u.id}>
                <Td className="font-medium">{u.username}</Td>
                <Td>
                  <Select value={u.role} disabled={u.id === user?.id} onChange={async (e) => {
                    try { await api.put(`/api/users/${u.id}`, { role: e.target.value, disabled: u.disabled }); qc.invalidateQueries({ queryKey: ['users'] }) } catch (x) { setErr(x) }
                  }}>
                    <option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option>
                  </Select>
                </Td>
                <Td className="text-xs text-slate-500">{ago(u.last_login_at)}</Td>
                <Td>{u.disabled ? <Badge tone="red">disabled</Badge> : <Badge tone="green">active</Badge>}</Td>
                <Td>{u.id !== user?.id && <div className="flex gap-1">
                  <Button size="sm" onClick={async () => { try { await api.put(`/api/users/${u.id}`, { role: u.role, disabled: !u.disabled }); qc.invalidateQueries({ queryKey: ['users'] }) } catch (x) { setErr(x) } }}>{u.disabled ? 'Enable' : 'Disable'}</Button>
                  <Button size="sm" variant="ghost" onClick={async () => { if (confirm(`Delete ${u.username}?`)) { try { await api.del(`/api/users/${u.id}`); qc.invalidateQueries({ queryKey: ['users'] }) } catch (x) { setErr(x) } } }}><Trash2 className="size-3.5 text-red-600" /></Button>
                </div>}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
        <div className="p-3"><ErrorBox error={err} /></div>
      </Card>
      <Card title="Add user">
        <div className="space-y-3">
          <Field label="Username"><Input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>
          <Field label="Password" hint="At least 8 characters"><Input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" /></Field>
          <Field label="Role" hint="viewer: read · operator: discover, edit context, CLI · admin: everything">
            <Select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })} className="w-full">
              <option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option>
            </Select>
          </Field>
          <Button variant="primary" className="w-full" onClick={async () => {
            try { await api.post('/api/users', f); setF({ username: '', password: '', role: 'viewer' }); qc.invalidateQueries({ queryKey: ['users'] }) } catch (x) { setErr(x) }
          }}>Create user</Button>
        </div>
      </Card>
    </div>
  )
}

function Audit() {
  const q = useQuery({ queryKey: ['audit'], queryFn: () => api.get<{ id: number; ts: string; username: string; action: string; target: string; detail: Record<string, unknown> }[]>('/api/audit') })
  return (
    <Card padded={false} title="Audit log">
      {q.isLoading ? <Loading /> : (
        <Table>
          <thead><tr><Th>Time</Th><Th>User</Th><Th>Action</Th><Th>Target</Th><Th>Detail</Th></tr></thead>
          <tbody>{q.data?.map((a) => (
            <tr key={a.id}><Td className="whitespace-nowrap text-xs text-slate-500">{dateTime(a.ts)}</Td><Td>{a.username || '—'}</Td>
              <Td className="font-mono text-xs">{a.action}</Td><Td className="text-xs">{a.target}</Td>
              <Td className="font-mono text-xs text-slate-500">{Object.keys(a.detail ?? {}).length ? JSON.stringify(a.detail) : ''}</Td></tr>
          ))}</tbody>
        </Table>
      )}
    </Card>
  )
}

function CLISessions() {
  const q = useQuery({ queryKey: ['cli-sessions'], queryFn: () => api.get<Record<string, any>[]>('/api/cli-sessions'), refetchInterval: 10_000 })
  const [transcript, setTranscript] = useState<{ id: number; text: string } | null>(null)
  return (
    <Card padded={false} title="CLI sessions">
      {q.isLoading ? <Loading /> : !q.data?.length ? <Empty title="No CLI sessions yet" /> : (
        <Table>
          <thead><tr><Th>User</Th><Th>Device</Th><Th>Protocol</Th><Th>Started</Th><Th>Ended</Th><Th>Bytes in/out</Th><Th /></tr></thead>
          <tbody>{q.data.map((s) => (
            <tr key={s.id}>
              <Td>{s.username}<div className="text-xs text-slate-400">{s.client_addr}</div></Td>
              <Td>{s.device}<div className="font-mono text-xs text-slate-400">{s.remote_addr}</div></Td>
              <Td><Badge tone={s.protocol === 'telnet' ? 'amber' : 'slate'}>{s.protocol}</Badge></Td>
              <Td className="text-xs">{dateTime(s.started_at)}</Td>
              <Td className="text-xs">{s.ended_at ? <>{dateTime(s.ended_at)}<div className="text-slate-400">{s.end_reason}</div></> : <Badge tone="green">active</Badge>}</Td>
              <Td className="text-xs tabular-nums">{s.bytes_in} / {s.bytes_out}</Td>
              <Td><div className="flex gap-1">
                <Button size="sm" onClick={async () => { const r = await fetch(`/api/cli-sessions/${s.id}/transcript`); setTranscript({ id: s.id, text: await r.text() }) }}>Transcript</Button>
                {!s.ended_at && <Button size="sm" variant="danger" onClick={() => api.post(`/api/cli-sessions/${s.id}/terminate`).then(() => q.refetch())}>Terminate</Button>}
              </div></Td>
            </tr>
          ))}</tbody>
        </Table>
      )}
      <Modal open={!!transcript} onClose={() => setTranscript(null)} title={`Session #${transcript?.id} transcript`} wide>
        <pre className="max-h-[60vh] overflow-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-100">{transcript?.text.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '')}</pre>
      </Modal>
    </Card>
  )
}

function Account() {
  const [f, setF] = useState({ current: '', new: '' })
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<unknown>(null)
  return (
    <Card title="Change password" className="max-w-md">
      <div className="space-y-3">
        <Field label="Current password"><Input type="password" value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} autoComplete="current-password" /></Field>
        <Field label="New password" hint="At least 8 characters"><Input type="password" value={f.new} onChange={(e) => setF({ ...f, new: e.target.value })} autoComplete="new-password" /></Field>
        <Button variant="primary" onClick={async () => {
          try { await api.post('/api/auth/password', f); setMsg('Password changed. Please sign in again.'); setTimeout(() => location.reload(), 1500) } catch (e) { setErr(e) }
        }}>Change password</Button>
        {msg && <div className="text-sm text-emerald-700">{msg}</div>}
        <ErrorBox error={err} />
      </div>
    </Card>
  )
}
