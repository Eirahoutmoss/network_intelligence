import { useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, ChevronDown, ChevronRight, Info } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import { useAuth } from '@/lib/auth'
import { DiscoveryProgress, useRunStream } from './DiscoveryProgress'
import { Button, ErrorBox, Field, Input, Modal, Select } from './ui'

interface Form {
  ip: string
  username: string
  password: string
  version: string
  community: string
  security_level: string
  auth_protocol: string
  priv_protocol: string
  priv_password: string
  context: string
  port: string
  depth: string
  scope: string
  active: boolean
  ssh_user: string
  ssh_pass: string
}

const empty: Form = {
  ip: '', username: '', password: '', version: 'auto', community: '', security_level: '', auth_protocol: 'SHA',
  priv_protocol: 'AES', priv_password: '', context: '', port: '', depth: '3', scope: '', active: false, ssh_user: '', ssh_pass: '',
}

export function AddDeviceDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { info } = useAuth()
  const [f, setF] = useState<Form>(empty)
  const [advanced, setAdvanced] = useState(false)
  const [runId, setRunId] = useState<number | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const run = useRunStream(runId)
  const qc = useQueryClient()
  const navigate = useNavigate()
  const set = (k: keyof Form, v: string | boolean) => setF((p) => ({ ...p, [k]: v }))
  const done = run && run.status !== 'queued' && run.status !== 'running'

  const close = () => {
    if (done) qc.invalidateQueries()
    setRunId(null)
    setError(null)
    setF(empty)
    onClose()
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const v2 = f.version === '2c' || (f.version === 'auto' && !f.username && (f.community || f.password))
      const snmp: Record<string, unknown> = v2
        ? { version: '2c', community: f.community || f.password }
        : {
            version: '3', username: f.username, password: f.password,
            security_level: f.security_level || undefined, auth_protocol: f.auth_protocol,
            priv_protocol: f.priv_password ? f.priv_protocol : undefined, priv_password: f.priv_password || undefined,
            context: f.context || undefined,
          }
      if (f.port) snmp.port = Number(f.port)
      const body: Record<string, unknown> = { ip: f.ip.trim(), snmp }
      if (advanced) {
        body.options = {
          max_depth: Number(f.depth),
          scope: f.scope.split(/[\s,]+/).filter(Boolean),
          active_fingerprint: f.active,
          try_all_credentials: true,
        }
      }
      if (f.ssh_user) body.ssh = { username: f.ssh_user, password: f.ssh_pass }
      const r = await api.post<{ run_id: number }>('/api/devices', body)
      setRunId(r.run_id)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  const demo = info?.simulator
  return (
    <Modal
      open={open}
      onClose={close}
      title={runId ? 'Discovering your network' : 'Add Device'}
      wide={!!runId}
      footer={
        runId ? (
          <>
            {done && run?.status === 'completed' && (
              <>
                <Button onClick={() => { close(); navigate('/topology') }}>View topology</Button>
                <Button onClick={() => { close(); navigate('/explore') }}>Ask a question</Button>
              </>
            )}
            <Button variant={done ? 'primary' : 'secondary'} onClick={close}>
              {done ? 'Done' : 'Run in background'}
            </Button>
          </>
        ) : (
          <>
            <Button variant="ghost" onClick={close}>Cancel</Button>
            <Button variant="primary" type="submit" form="add-device" loading={busy}>Add Device</Button>
          </>
        )
      }
    >
      {runId ? (
        <div className="space-y-3">
          <DiscoveryProgress run={run} compact />
          {done && run?.status === 'completed' && (
            <div className="flex items-center gap-2 rounded-lg bg-emerald-50 px-3 py-2.5 text-sm font-medium text-emerald-800 ring-1 ring-emerald-200">
              <CheckCircle2 className="size-5" />
              Device ready — {run.summary?.devices ?? 0} network devices, {run.summary?.endpoints ?? 0} endpoints, {run.summary?.edges ?? 0} links.
            </div>
          )}
        </div>
      ) : (
        <form id="add-device" onSubmit={submit} className="space-y-4">
          {demo && (
            <div className="flex gap-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900 ring-1 ring-amber-200">
              <Info className="mt-0.5 size-4 shrink-0" />
              <div>
                Demo network is active. Try IP <b>10.20.99.1</b>, username <b>prometheus</b>, password <b>nexus-demo-pass</b>.{' '}
                <button type="button" className="underline" onClick={() => setF({ ...f, ip: '10.20.99.1', username: 'prometheus', password: 'nexus-demo-pass' })}>
                  Fill in
                </button>
              </div>
            </div>
          )}
          <Field label="IP address">
            <Input autoFocus required value={f.ip} onChange={(e) => set('ip', e.target.value)} placeholder="10.2.33.1" inputMode="decimal" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="SNMP username" hint="Leave empty to use an SNMPv2c community">
              <Input value={f.username} onChange={(e) => set('username', e.target.value)} placeholder="prometheus" autoComplete="off" />
            </Field>
            <Field label={f.username ? 'SNMP password' : 'SNMP password / community'}>
              <Input type="password" value={f.password} onChange={(e) => set('password', e.target.value)} autoComplete="new-password" required={!f.community} />
            </Field>
          </div>
          <button type="button" onClick={() => setAdvanced(!advanced)} className="flex items-center gap-1 text-sm font-medium text-slate-600 hover:text-slate-900">
            {advanced ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />} Advanced options
          </button>
          {advanced && (
            <div className="space-y-4 rounded-lg border border-slate-200 bg-slate-50/50 p-3">
              <div className="grid grid-cols-3 gap-3">
                <Field label="SNMP version">
                  <Select value={f.version} onChange={(e) => set('version', e.target.value)} className="w-full">
                    <option value="auto">Automatic</option>
                    <option value="3">v3</option>
                    <option value="2c">v2c</option>
                  </Select>
                </Field>
                <Field label="Port">
                  <Input value={f.port} onChange={(e) => set('port', e.target.value)} placeholder="161" />
                </Field>
                <Field label="Community (v2c)">
                  <Input value={f.community} onChange={(e) => set('community', e.target.value)} placeholder="public" />
                </Field>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <Field label="Security level">
                  <Select value={f.security_level} onChange={(e) => set('security_level', e.target.value)} className="w-full">
                    <option value="">Automatic</option>
                    <option value="noAuthNoPriv">noAuthNoPriv</option>
                    <option value="authNoPriv">authNoPriv</option>
                    <option value="authPriv">authPriv</option>
                  </Select>
                </Field>
                <Field label="Auth protocol">
                  <Select value={f.auth_protocol} onChange={(e) => set('auth_protocol', e.target.value)} className="w-full">
                    {['SHA', 'SHA256', 'SHA512', 'SHA224', 'SHA384', 'MD5'].map((p) => <option key={p}>{p}</option>)}
                  </Select>
                </Field>
                <Field label="Context">
                  <Input value={f.context} onChange={(e) => set('context', e.target.value)} />
                </Field>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Privacy protocol">
                  <Select value={f.priv_protocol} onChange={(e) => set('priv_protocol', e.target.value)} className="w-full">
                    {['AES', 'AES192', 'AES256', 'AES192C', 'AES256C', 'DES'].map((p) => <option key={p}>{p}</option>)}
                  </Select>
                </Field>
                <Field label="Privacy password" hint="Only for authPriv">
                  <Input type="password" value={f.priv_password} onChange={(e) => set('priv_password', e.target.value)} autoComplete="new-password" />
                </Field>
              </div>
              <div className="border-t border-slate-200 pt-3">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Discovery scope</div>
                <div className="grid grid-cols-3 gap-3">
                  <Field label="Neighbor hops" hint="0 = this device only">
                    <Select value={f.depth} onChange={(e) => set('depth', e.target.value)} className="w-full">
                      {[0, 1, 2, 3, 4, 5].map((d) => <option key={d} value={d}>{d}</option>)}
                    </Select>
                  </Field>
                  <Field label="Allowed networks" hint="Default: the seed's /16" className="col-span-2">
                    <Input value={f.scope} onChange={(e) => set('scope', e.target.value)} placeholder="10.2.0.0/16, 10.3.0.0/16" />
                  </Field>
                </div>
                <label className="mt-3 flex items-start gap-2 text-sm text-slate-700">
                  <input type="checkbox" checked={f.active} onChange={(e) => set('active', e.target.checked)} className="mt-0.5" />
                  <span>
                    Identify endpoints actively (NetBIOS, SMB, HTTP, service ports) inside the allowed networks.
                    <span className="block text-xs text-slate-500">Only enable on networks you are authorized to scan.</span>
                  </span>
                </label>
              </div>
              <div className="border-t border-slate-200 pt-3">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">CLI access (optional)</div>
                <div className="grid grid-cols-2 gap-3">
                  <Field label="SSH username"><Input value={f.ssh_user} onChange={(e) => set('ssh_user', e.target.value)} autoComplete="off" /></Field>
                  <Field label="SSH password"><Input type="password" value={f.ssh_pass} onChange={(e) => set('ssh_pass', e.target.value)} autoComplete="new-password" /></Field>
                </div>
              </div>
            </div>
          )}
          <p className="text-xs text-slate-500">Credentials are encrypted and never shown again. Discovery follows LLDP/CDP neighbors inside the allowed networks only.</p>
          <ErrorBox error={error} />
        </form>
      )}
    </Modal>
  )
}
