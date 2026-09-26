import { useMutation } from '@tanstack/react-query'
import { Database, Filter, Info, Link2, Search, Sparkles } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '@/api/client'
import type { ExploreAnswer, ExploreQuery } from '@/api/types'
import { Badge, Button, Card, Empty, ErrorBox, Field, Input, Loading, PageHeader, Select, Table, Td, Th } from '@/components/ui'
import { DeviceTable } from '@/devices/DeviceTable'
import { DEVICE_TYPES, speed, typeLabel } from '@/lib/format'

const EXAMPLES = [
  'Kaç switch var?',
  'HP yazıcıları göster',
  'Kaç tane Canon yazıcı var?',
  'Laboratuvarda Windows XP kullanan cihazları göster',
  "SW-CORE-01'e bağlı cihazları göster",
  '10.20.30.0/24 ağında ne var?',
  'Fiber bağlantıları göster',
  "Kat 2'de kaç switch var?",
  'Son 30 günde switch portu değişen cihazları göster',
  'Show IP phones',
]

function loadHistory(): string[] {
  try {
    return JSON.parse(localStorage.getItem('nexus.explore.history') ?? '[]')
  } catch {
    return []
  }
}

export default function ExplorePage() {
  const [params, setParams] = useSearchParams()
  const [question, setQuestion] = useState(params.get('q') ?? '')
  const [history, setHistory] = useState<string[]>(loadHistory)
  const [showFilters, setShowFilters] = useState(false)
  const ask = useMutation({ mutationFn: (q: string) => api.post<ExploreAnswer>('/api/explore', { question: q }) })
  const run = useMutation({ mutationFn: (q: ExploreQuery) => api.post<ExploreAnswer>('/api/explore/query', q) })
  const answer = run.data && run.submittedAt > ask.submittedAt ? run.data : ask.data
  const busy = ask.isPending || run.isPending
  const error = ask.error ?? run.error

  const submit = (q: string) => {
    if (!q.trim()) return
    setQuestion(q)
    setParams({ q }, { replace: true })
    ask.mutate(q)
    const h = [q, ...history.filter((x) => x !== q)].slice(0, 8)
    setHistory(h)
    try {
      localStorage.setItem('nexus.explore.history', JSON.stringify(h))
    } catch {
      /* private mode */
    }
  }
  useEffect(() => {
    const q = params.get('q')
    if (q && q !== ask.variables) submit(q)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.get('q')])

  return (
    <div className="p-6">
      <PageHeader title="Explore Network" subtitle="Ask in Turkish or English. Answers come only from discovered data — nothing is guessed." />
      <form
        onSubmit={(e) => {
          e.preventDefault()
          submit(question)
        }}
        className="relative"
      >
        <Sparkles className="pointer-events-none absolute left-4 top-1/2 size-5 -translate-y-1/2 text-brand-600" />
        <input
          autoFocus
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="e.g. Laboratuvarda Windows XP kullanan cihazları göster"
          className="h-13 w-full rounded-xl border border-slate-200 bg-white pl-12 pr-32 text-base shadow-sm placeholder:text-slate-400 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15"
        />
        <Button variant="primary" type="submit" loading={ask.isPending} className="absolute right-2 top-1/2 -translate-y-1/2">
          <Search className="size-4" /> Ask
        </Button>
      </form>
      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        {(history.length ? history : EXAMPLES).map((x) => (
          <button key={x} onClick={() => submit(x)} className="rounded-full border border-slate-200 bg-white px-2.5 py-1 text-xs text-slate-600 hover:border-brand-300 hover:text-brand-800">
            {x}
          </button>
        ))}
        <button onClick={() => setShowFilters(!showFilters)} className="ml-auto inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-slate-900">
          <Filter className="size-3.5" /> Structured filters
        </button>
      </div>
      {showFilters && <StructuredFilters onRun={(q) => run.mutate(q)} />}
      <div className="mt-5">
        {busy && <Loading label="Looking it up…" />}
        {error && <ErrorBox error={error} />}
        {!busy && answer && <AnswerView a={answer} onAsk={submit} />}
        {!busy && !answer && !error && (
          <Card>
            <Empty icon={<Sparkles className="size-10" />} title="What do you want to know about your network?">
              Try one of the examples above. Nexus translates your question into a precise filter and shows how it was understood.
            </Empty>
          </Card>
        )}
      </div>
    </div>
  )
}

function AnswerView({ a, onAsk }: { a: ExploreAnswer; onAsk: (q: string) => void }) {
  return (
    <div className="space-y-4 animate-fade-in">
      <Card>
        <div className="text-lg font-semibold text-slate-900">{a.text}</div>
        {a.interpretation.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-slate-500">Understood as:</span>
            {a.interpretation.map((x) => <Badge key={x} tone="brand">{x}</Badge>)}
            {a.interpreter === 'llm' && <Badge tone="violet" title="An AI model translated the question into filters; results come from the database">AI-interpreted</Badge>}
          </div>
        )}
        {a.notes?.map((n) => (
          <div key={n} className="mt-2 flex items-start gap-1.5 text-sm text-amber-800">
            <Info className="mt-0.5 size-4 shrink-0" /> {n}
          </div>
        ))}
        <div className="mt-3 flex items-center gap-1.5 text-xs text-slate-400">
          <Database className="size-3.5" /> {a.sources.join(' · ')}
        </div>
        {!a.recognized && a.suggestions && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {a.suggestions.map((s) => (
              <button key={s} onClick={() => onAsk(s)} className="rounded-full border border-slate-200 px-2.5 py-1 text-xs text-slate-600 hover:border-brand-300">{s}</button>
            ))}
          </div>
        )}
      </Card>
      {a.jacks && a.jacks.length > 0 && (
        <Card title="Wall jack path">
          {a.jacks.map((j) => (
            <div key={j.id} className="flex flex-wrap items-center gap-2 text-sm">
              <Badge tone="violet">{j.location} / {j.label}</Badge>
              {j.patch_panel && <><span className="text-slate-400">→</span><Badge>{j.patch_panel} / {j.patch_port}</Badge></>}
              {j.switch && <><span className="text-slate-400">→</span><Link to={`/devices/${j.switch_id}`}><Badge tone="brand">{j.switch} / {j.port}</Badge></Link></>}
              {j.seen_count !== undefined && j.seen_count !== null && <span className="text-slate-500">{j.seen_count} devices seen</span>}
            </div>
          ))}
        </Card>
      )}
      {a.devices && a.devices.length > 0 && (
        <Card padded={false} title={`${a.count} result${a.count === 1 ? '' : 's'}`}>
          <DeviceTable rows={a.devices} showMoved={!!a.query.port_changed_days} />
        </Card>
      )}
      {a.connections && a.connections.length > 0 && (
        <Card padded={false} title={`${a.connections.length} links`}>
          <Table>
            <thead><tr><Th>From</Th><Th>To</Th><Th>Medium</Th><Th>Speed</Th><Th>Seen by</Th></tr></thead>
            <tbody>
              {a.connections.map((c, i) => (
                <tr key={i}>
                  <Td><Link to={`/devices/${c.a_id}`} className="font-medium hover:underline">{c.a}</Link> <span className="text-slate-500">{c.a_port}</span></Td>
                  <Td><Link to={`/devices/${c.b_id}`} className="font-medium hover:underline">{c.b}</Link> <span className="text-slate-500">{c.b_port}</span></Td>
                  <Td><Badge tone={c.medium === 'fiber' ? 'blue' : 'slate'}>{c.medium}</Badge></Td>
                  <Td>{speed(c.speed_bps)}</Td>
                  <Td className="text-xs"><Link2 className="mr-1 inline size-3" />{c.sources.join(', ')}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </div>
  )
}

function StructuredFilters({ onRun }: { onRun: (q: ExploreQuery) => void }) {
  const [f, setF] = useState({ type: '', vendor: '', os: '', location: '', floor: '', subnet: '', connected: '' })
  return (
    <Card className="mt-3">
      <form
        className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7"
        onSubmit={(e) => {
          e.preventDefault()
          onRun({
            intent: 'list', subject: 'devices', lang: 'en',
            types: f.type ? [f.type] : undefined, vendors: f.vendor ? [f.vendor] : undefined, os: f.os || undefined,
            location: f.location || undefined, floor: f.floor ? Number(f.floor) : undefined, subnet: f.subnet || undefined,
            connected_to: f.connected || undefined,
          })
        }}
      >
        <Field label="Type">
          <Select value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })} className="w-full">
            <option value="">Any</option>
            {DEVICE_TYPES.map((t) => <option key={t} value={t}>{typeLabel(t)}</option>)}
          </Select>
        </Field>
        <Field label="Vendor"><Input value={f.vendor} onChange={(e) => setF({ ...f, vendor: e.target.value })} placeholder="HP" /></Field>
        <Field label="OS"><Input value={f.os} onChange={(e) => setF({ ...f, os: e.target.value })} placeholder="Windows XP" /></Field>
        <Field label="Location"><Input value={f.location} onChange={(e) => setF({ ...f, location: e.target.value })} placeholder="Laboratory" /></Field>
        <Field label="Floor"><Input value={f.floor} onChange={(e) => setF({ ...f, floor: e.target.value })} placeholder="2" /></Field>
        <Field label="Network"><Input value={f.subnet} onChange={(e) => setF({ ...f, subnet: e.target.value })} placeholder="10.20.30.0/24" /></Field>
        <Field label="Connected to"><Input value={f.connected} onChange={(e) => setF({ ...f, connected: e.target.value })} placeholder="SW-CORE-01" /></Field>
        <div className="col-span-full flex justify-end">
          <Button variant="primary" type="submit"><Filter className="size-4" /> Apply</Button>
        </div>
      </form>
    </Card>
  )
}
