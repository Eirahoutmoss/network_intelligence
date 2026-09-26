import { useMutation } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Download, HardDriveDownload, Info, Stethoscope, XCircle } from 'lucide-react'
import { useState } from 'react'
import { api, download } from '@/api/client'
import { Button, Card, ErrorBox, Field, Input } from '@/components/ui'
import { dateTime } from '@/lib/format'
import { useAuth } from '@/lib/auth'

interface Check {
  component: string
  status: 'ok' | 'warning' | 'failed'
  detail: string
  hint?: string
}

interface DiagResult {
  status: 'ok' | 'warning' | 'failed'
  checks: Check[]
  version: string
  checked_at: string
}

const icon = {
  ok: <CheckCircle2 className="size-4 text-emerald-600" />,
  warning: <AlertTriangle className="size-4 text-amber-500" />,
  failed: <XCircle className="size-4 text-red-600" />,
}

export function Maintenance() {
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Diagnostics />
      <Backup />
    </div>
  )
}

function Diagnostics() {
  const run = useMutation({ mutationFn: () => api.get<DiagResult>('/api/admin/diagnostics') })
  const [bundleErr, setBundleErr] = useState<unknown>(null)
  const [exporting, setExporting] = useState(false)
  return (
    <Card
      title={<span className="flex items-center gap-2"><Stethoscope className="size-4" /> Diagnostics</span>}
      actions={
        <>
          <Button size="sm" variant="primary" loading={run.isPending} onClick={() => run.mutate()}>Run health check</Button>
          <Button size="sm" loading={exporting} onClick={async () => {
            setBundleErr(null)
            setExporting(true)
            try {
              await download('GET', '/api/admin/diagnostics/bundle', 'nexus-diagnostics.zip')
            } catch (e) {
              setBundleErr(e)
            } finally {
              setExporting(false)
            }
          }}><Download className="size-3.5" /> Export diagnostic bundle</Button>
        </>
      }
    >
      <p className="text-xs text-slate-500">
        The bundle contains versions, health checks, configuration and recent logs for support. Passwords, SNMP communities, keys,
        tokens and cookies are removed automatically.
      </p>
      <ErrorBox error={run.error ?? bundleErr} />
      {run.data && (
        <div className="mt-3">
          <div className="mb-2 flex items-center gap-2 text-sm font-medium">
            {icon[run.data.status]}
            {run.data.status === 'ok' ? 'All checks passed' : run.data.status === 'warning' ? 'Passed with warnings' : 'Some checks failed'}
            <span className="ml-auto text-xs font-normal text-slate-400">{dateTime(run.data.checked_at)}</span>
          </div>
          <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200" data-testid="health-checks">
            {run.data.checks.map((c) => (
              <li key={c.component} className="flex gap-2 px-3 py-2 text-sm">
                <span className="mt-0.5">{icon[c.status]}</span>
                <div className="min-w-0">
                  <div className="font-medium text-slate-800">{c.component}</div>
                  <div className="text-xs text-slate-600">{c.detail}</div>
                  {c.hint && c.status !== 'ok' && <div className="mt-0.5 text-xs text-amber-700">{c.hint}</div>}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  )
}

function Backup() {
  const [pass, setPass] = useState('')
  const [pass2, setPass2] = useState('')
  const [withKey, setWithKey] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<unknown>(null)
  const [done, setDone] = useState(false)
  const bad = withKey && (pass.length < 12 || pass !== pass2)
  return (
    <Card title={<span className="flex items-center gap-2"><HardDriveDownload className="size-4" /> Backup</span>}>
      <div className="space-y-3 text-sm">
        <p className="text-xs text-slate-500">
          A backup contains the whole inventory: devices, topology, locations, users and settings. Stored device credentials stay
          encrypted. Nexus also writes a backup every day and before every upgrade into its backups folder.
        </p>
        <label className="flex items-start gap-2 text-sm text-slate-700">
          <input type="checkbox" className="mt-0.5" checked={withKey} onChange={(e) => setWithKey(e.target.checked)} />
          <span>
            Include the encryption key, protected by a passphrase
            <span className="block text-xs text-slate-500">Needed to use the stored device credentials after restoring on another computer.</span>
          </span>
        </label>
        {withKey && (
          <div className="grid grid-cols-2 gap-3">
            <Field label="Passphrase" hint="At least 12 characters">
              <Input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" />
            </Field>
            <Field label="Repeat passphrase">
              <Input type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} autoComplete="new-password" />
            </Field>
          </div>
        )}
        <Button variant="primary" loading={busy} disabled={bad} onClick={async () => {
          setErr(null)
          setDone(false)
          setBusy(true)
          try {
            await download('POST', '/api/admin/backup', 'nexus.nxbackup', { passphrase: withKey ? pass : '' })
            setDone(true)
            setPass('')
            setPass2('')
          } catch (e) {
            setErr(e)
          } finally {
            setBusy(false)
          }
        }}><Download className="size-3.5" /> Download backup</Button>
        {done && <div className="text-sm text-emerald-700">Backup downloaded. Keep it somewhere safe{withKey ? ' and remember the passphrase' : ''}.</div>}
        <ErrorBox error={err} />
        <div className="flex gap-2 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600 ring-1 ring-slate-200">
          <Info className="mt-0.5 size-4 shrink-0" />
          <div>
            <b>Restore:</b> stop the Nexus service, then on the Nexus computer run as administrator:
            <code className="mt-1 block rounded bg-white px-1.5 py-1 font-mono text-[11px] ring-1 ring-slate-200">nexus.exe --config "%ProgramData%\Nexus\config\nexus.env" restore FILE.nxbackup</code>
            A safety backup of the current data is written first.
          </div>
        </div>
      </div>
    </Card>
  )
}

export function About() {
  const { info } = useAuth()
  return (
    <Card title="About" className="max-w-md">
      <div className="space-y-3 text-sm text-slate-700">
        <div>
          <div className="text-base font-semibold text-slate-900">Nexus v1</div>
          <div className="text-slate-500">Network Intelligence Platform · version {info?.version ?? '—'}</div>
        </div>
        <div className="border-t border-slate-100 pt-3">
          <div className="text-xs uppercase tracking-wide text-slate-400">Designed and developed by</div>
          <div className="font-medium text-slate-900">Hasan Güler</div>
          <p className="mt-1 text-sm italic text-slate-500">“Sen ağa erişimi ver. Gerisini sistem anlamaya çalışsın.”</p>
        </div>
        <p className="border-t border-slate-100 pt-3 text-xs text-slate-500">Licensed under the Apache License 2.0. Third-party notices are included with the installation.</p>
      </div>
    </Card>
  )
}
