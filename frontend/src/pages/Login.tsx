import { Network } from 'lucide-react'
import { useState } from 'react'
import { Button, ErrorBox, Field, Input } from '@/components/ui'
import { useAuth } from '@/lib/auth'

export function LoginPage() {
  const { login } = useAuth()
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  return (
    <div className="flex min-h-full items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-brand-900 p-4">
      <form
        className="w-full max-w-sm rounded-2xl bg-white p-7 shadow-2xl"
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
      >
        <div className="mb-6 flex items-center gap-3">
          <div className="grid size-10 place-items-center rounded-xl bg-brand-700 text-white">
            <Network className="size-5" />
          </div>
          <div>
            <div className="text-lg font-semibold text-slate-900">Nexus</div>
            <div className="text-sm text-slate-500">More than monitoring: understanding.</div>
          </div>
        </div>
        <div className="space-y-3">
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
        </div>
      </form>
    </div>
  )
}
