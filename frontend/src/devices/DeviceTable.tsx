import { Link } from 'react-router-dom'
import type { DeviceRow } from '@/api/types'
import { DeviceIcon } from '@/components/DeviceIcon'
import { Badge, Confidence, StatusDot, Table, Td, Th } from '@/components/ui'
import { ago, typeLabel } from '@/lib/format'

export function DeviceTable({ rows, showMoved, selectable, selected, onSelect }: {
  rows: DeviceRow[]
  showMoved?: boolean
  selectable?: boolean
  selected?: Set<number>
  onSelect?: (id: number, on: boolean) => void
}) {
  return (
    <Table>
      <thead>
        <tr>
          {selectable && <Th className="w-8" />}
          <Th>Name</Th>
          <Th>Type</Th>
          <Th>Vendor / model</Th>
          <Th>OS</Th>
          <Th>IP / MAC</Th>
          <Th>Connected to</Th>
          <Th>Location</Th>
          <Th>{showMoved ? 'Moved' : 'Last seen'}</Th>
        </tr>
      </thead>
      <tbody>
        {rows.map((d) => (
          <tr key={d.id} className="hover:bg-slate-50/70">
            {selectable && (
              <Td>
                <input type="checkbox" checked={selected?.has(d.id) ?? false} onChange={(e) => onSelect?.(d.id, e.target.checked)} />
              </Td>
            )}
            <Td>
              <Link to={`/devices/${d.id}`} className="flex items-center gap-2 font-medium text-slate-900 hover:text-brand-700">
                <StatusDot status={d.status} />
                <span className="max-w-[16rem] truncate">{d.name}</span>
                {d.managed && <Badge tone="brand">SNMP</Badge>}
              </Link>
            </Td>
            <Td>
              <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
                <DeviceIcon type={d.device_type} /> {typeLabel(d.device_type)}
                {!d.type_overridden && d.device_type !== 'unknown' && <Confidence value={d.device_type_confidence} />}
              </span>
            </Td>
            <Td>
              <div className="whitespace-nowrap">{d.vendor ?? <span className="text-slate-400">—</span>}</div>
              {d.model && <div className="text-xs text-slate-500">{d.model}</div>}
            </Td>
            <Td>
              {d.os_name ? (
                <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
                  {d.os_name} {!d.managed && <Confidence value={d.os_confidence} />}
                </span>
              ) : (
                <span className="text-slate-400">—</span>
              )}
            </Td>
            <Td>
              <div className="font-mono text-xs">{d.ip ?? '—'}</div>
              <div className="font-mono text-xs text-slate-400">{d.mac}</div>
            </Td>
            <Td>
              {d.switch_id ? (
                <Link to={`/devices/${d.switch_id}`} className="whitespace-nowrap hover:underline">
                  {d.switch_name} <span className="text-slate-500">{d.switch_port}</span>
                  {d.vlan ? <span className="ml-1 text-xs text-slate-400">VLAN {d.vlan}</span> : null}
                </Link>
              ) : (
                <span className="text-slate-400">—</span>
              )}
            </Td>
            <Td>
              {d.location_path ? (
                <span className="text-xs" title={d.location_source === 'user' ? 'Set by you' : d.location_source === 'jack' ? 'From wall jack mapping' : 'Inferred from the switch it is connected to'}>
                  {d.location_path}
                  {d.location_source !== 'user' && <span className="ml-1 text-slate-400">(inferred)</span>}
                </span>
              ) : (
                <span className="text-slate-400">—</span>
              )}
            </Td>
            <Td className="whitespace-nowrap text-xs text-slate-500">
              {showMoved ? (
                <>
                  {ago(d.moved_at)} <div className="text-slate-400">from {d.previous_port}</div>
                </>
              ) : (
                ago(d.last_seen)
              )}
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  )
}
