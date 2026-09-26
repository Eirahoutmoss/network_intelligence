import { useQuery } from '@tanstack/react-query'
import { Monitor, Network, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { api } from '@/api/client'
import { Button, ErrorBox, Field, Input } from '@/components/ui'
import { useAuth } from '@/lib/auth'

interface SetupStatus {
  required: boolean
  allowed: boolean
}

export function LoginPage() {
  const setup = useQuery({ queryKey: ['setup'], queryFn: () => api.get<SetupStatus>('/api/setup'), retry: 1 })
  return (
    <div className="flex min-h-full flex-col items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-brand-900 p-4">
      <div className="w-full max-w-sm rounded-2xl bg-white p-7 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="grid size-10 place-items-center rounded-xl bg-brand-700 text-white">
            <Network className="size-5" />
          </div>
          <div>
            <div className="text-lg font-semibold text-slate-900">Nexus</div>
            <div className="text-sm text-slate-500">More than monitoring: understanding.</div>
          </div>
        </div>
        {setup.data?.required ? setup.data.allowed ? <SetupForm /> : <SetupElsewhere /> : <LoginForm />}
      </div>
      <p className="mt-6 text-center text-xs text-slate-400">
        Nexus v1 · Network Intelligence Platform · Designed and developed by Hasan Güler
      </p>
    </div>
  )
}

function LoginForm() {
  const { login } = useAuth()
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        setBusy(true)
        setErr(null)
        try {
          await login(u, p)
        } catch (x) {
          setErr(x)
        } finally {
          setBusy(false)
        }
      }}
      className="space-y-3"
    >
      <Field label="Username">
        <Input autoFocus value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" required />
      </Field>
      <Field label="Password">
        <Input type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" required />
      </Field>
      <ErrorBox error={err} />
      <Button variant="primary" type="submit" className="w-full" loading={busy}>
        Sign in
      </Button>
    </form>
  )
}

function SetupForm() {
  const { setup } = useAuth()
  const [u, setU] = useState('admin')
  const [p, setP] = useState('')
  const [p2, setP2] = useState('')
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const mismatch = p2 !== '' && p !== p2
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        if (p !== p2) return
        setBusy(true)
        setErr(null)
        try {
          await setup(u, p)
        } catch (x) {
          setErr(x)
        } finally {
          setBusy(false)
        }
      }}
      className="space-y-3"
    >
      <div className="flex gap-2 rounded-lg bg-brand-50 px-3 py-2.5 text-sm text-brand-900 ring-1 ring-brand-200">
        <ShieldCheck className="mt-0.5 size-4 shrink-0" />
        <div>
          <div className="font-medium">Welcome — create the administrator</div>
          <div className="text-xs text-brand-800">This is a new installation. The account you create here manages Nexus; no default password exists.</div>
        </div>
      </div>
      <Field label="Administrator username">
        <Input value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" required />
      </Field>
      <Field label="Password" hint="At least 10 characters">
        <Input autoFocus type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="new-password" minLength={10} required />
      </Field>
      <Field label="Repeat password">
        <Input type="password" value={p2} onChange={(e) => setP2(e.target.value)} autoComplete="new-password" required />
      </Field>
      {mismatch && <p className="text-xs text-red-600">The passwords do not match.</p>}
      <ErrorBox error={err} />
      <Button variant="primary" type="submit" className="w-full" loading={busy} disabled={mismatch || p.length < 10}>
        Create administrator
      </Button>
    </form>
  )
}

function SetupElsewhere() {
  return (
    <div className="flex gap-3 rounded-lg bg-amber-50 px-3 py-3 text-sm text-amber-900 ring-1 ring-amber-200">
      <Monitor className="mt-0.5 size-5 shrink-0" />
      <div>
        <div className="font-medium">Setup is not finished</div>
        <p className="mt-1 text-xs">
          For security, the first administrator can only be created on the computer where Nexus is installed. Open Nexus there
          (Start menu → Nexus), create the account, then sign in here.
        </p>
      </div>
    </div>
  )
}
