import { AlertTriangle, CheckCircle2, CircleSlash, Loader2, XCircle } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import type { DiscoveryRun, Step } from '@/api/types'
import { cn } from './ui'

function StepIcon({ s }: { s: Step['status'] }) {
  switch (s) {
    case 'done':
      return <CheckCircle2 className="size-4 text-emerald-600" />
    case 'failed':
      return <XCircle className="size-4 text-red-600" />
    case 'warning':
      return <AlertTriangle className="size-4 text-amber-500" />
    case 'skipped':
      return <CircleSlash className="size-4 text-slate-400" />
  }
  return <Loader2 className="size-4 animate-spin text-brand-600" />
}

// Live run state from the SSE stream (falls back to the snapshot).
export function useRunStream(runId: number | null) {
  const [run, setRun] = useState<DiscoveryRun | null>(null)
  useEffect(() => {
    if (!runId) return
    setRun(null)
    const es = new EventSource(`/api/discovery/runs/${runId}/stream`)
    es.addEventListener('snapshot', (e) => setRun(JSON.parse((e as MessageEvent).data)))
    es.addEventListener('update', (e) => {
      const m = JSON.parse((e as MessageEvent).data) as { step?: Step; status?: DiscoveryRun['status']; summary?: Record<string, any> }
      setRun((prev) => {
        if (!prev) return prev
        const next = { ...prev }
        if (m.step) {
          const steps = [...prev.steps]
          const i = steps.findIndex((x) => x.key === m.step!.key && x.device === m.step!.device && x.status === 'running')
          if (i >= 0) steps[i] = m.step
          else steps.push(m.step)
          next.steps = steps
        }
        if (m.status) next.status = m.status
        if (m.summary) next.summary = m.summary
        return next
      })
      if (m.status && m.status !== 'running') es.close()
    })
    es.onerror = () => {
      // the server closes the stream when the run ends; fetch the final state once
      es.close()
      fetch(`/api/discovery/runs/${runId}`, { credentials: 'same-origin' })
        .then((r) => (r.ok ? r.json() : null))
        .then((r) => r && setRun(r))
        .catch(() => undefined)
    }
    return () => es.close()
  }, [runId])
  return run
}

export function DiscoveryProgress({ run, compact }: { run: DiscoveryRun | null; compact?: boolean }) {
  const groups = useMemo(() => {
    // Order: run-level setup, one group per device, then run-level wrap-up.
    const g: { device: string; steps: Step[] }[] = [{ device: '#setup', steps: [] }]
    const tail: Step[] = []
    for (const s of run?.steps ?? []) {
      if (!s.device) {
        if (s.key === 'scope') g[0].steps.push(s)
        else tail.push(s)
        continue
      }
      const d = s.device
      let grp = g.find((x) => x.device === d)
      if (!grp) {
        grp = { device: d, steps: [] }
        g.push(grp)
      }
      grp.steps.push(s)
    }
    if (tail.length) g.push({ device: '#summary', steps: tail })
    return g.filter((x) => x.steps.length)
  }, [run])
  if (!run) {
    return (
      <div className="flex items-center gap-2 py-6 text-sm text-slate-500">
        <Loader2 className="size-4 animate-spin" /> Connecting…
      </div>
    )
  }
  return (
    <div className={cn('space-y-3', compact && 'max-h-[50vh] overflow-y-auto pr-1')}>
      {groups.map((g) => (
        <div key={g.device || 'global'} className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2">
          {!g.device.startsWith('#') && <div className="mb-1 font-mono text-xs font-medium text-slate-500">{g.device}</div>}
          <ul className="space-y-1">
            {g.steps.map((s, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span className="mt-0.5">
                  <StepIcon s={s.status} />
                </span>
                <span className={cn('font-medium', s.status === 'failed' ? 'text-red-700' : s.status === 'skipped' ? 'text-slate-400' : 'text-slate-700')}>{s.label}</span>
                {s.detail && <span className="min-w-0 truncate text-slate-500" title={s.detail}>— {s.detail}</span>}
              </li>
            ))}
          </ul>
        </div>
      ))}
      {run.status === 'failed' && run.error && <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{run.error}</div>}
    </div>
  )
}
