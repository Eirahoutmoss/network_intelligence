export type Role = 'viewer' | 'operator' | 'admin'

export interface User {
  id: number
  username: string
  role: Role
  disabled: boolean
  created_at: string
  last_login_at: string | null
}

export interface DeviceRow {
  id: number
  name: string
  hostname: string | null
  device_type: string
  device_type_confidence: number
  type_overridden: boolean
  vendor: string | null
  model: string | null
  os_name: string | null
  os_confidence: number
  ip: string | null
  mac: string | null
  managed: boolean
  status: 'up' | 'down' | 'unknown'
  discovered_via: string
  first_seen: string
  last_seen: string
  switch_id: number | null
  switch_name: string | null
  switch_port: string | null
  vlan: number | null
  attachment_confidence: number | null
  jack: string | null
  location_id: number | null
  location_source: 'user' | 'jack' | 'switch' | null
  location_path: string | null
  tags: string[]
  moved_at?: string | null
  previous_port?: string | null
}

export interface Evidence {
  attribute: string
  value: string
  source: string
  detail: string | null
  weight: number
}

export interface DeviceContext {
  display_name: string | null
  description: string | null
  department: string | null
  device_type_override: string | null
  location_id: number | null
  rack_id: number | null
  rack_unit: number | null
  tags: string[]
}

export interface DeviceDetail extends DeviceRow {
  facts: Record<string, any>
  addresses: { ip: string; prefix_len: number | null; source: string; first_seen: string; last_seen: string }[]
  macs: { mac: string; source: string; first_seen: string; last_seen: string }[]
  hostnames: { name: string; source: string; last_seen: string }[]
  evidence: Record<string, Evidence[]>
  context: DeviceContext
  attachment_history: {
    id: number
    switch: string
    switch_id: number
    port: string
    vlan: number | null
    source: string
    confidence: number
    started_at: string
    last_seen: string
    ended_at: string | null
  }[]
  sensors: { kind: string; name: string; value: number | null; unit: string | null; status: string | null }[]
  inventory: Record<string, any>[]
  fingerprint: Record<string, any>
  access: {
    ssh_credential_id: number | null
    telnet_credential_id: number | null
    telnet_enabled: boolean
    ssh_host_key: string | null
    telnet_allowed: boolean
  }
  stats: Record<string, number>
}

export interface Interface {
  id: number
  if_index: number
  name: string | null
  descr: string | null
  alias: string | null
  if_type: number | null
  mtu: number | null
  speed_bps: number | null
  mac: string | null
  admin_status: string | null
  oper_status: string | null
  duplex: string | null
  medium: string | null
  pvid: number | null
  in_bps: number | null
  out_bps: number | null
  in_errors: number | null
  out_errors: number | null
  is_uplink: boolean
  stp_state: string | null
  optic: { vendor: string | null; part_number: string | null; serial: string | null; type: string | null; rx_dbm: number | null; tx_dbm: number | null } | null
  vlans: number[]
  neighbor: { device_id: number | null; name: string | null; port: string | null; protocol: string } | null
  attached: number
  mac_count: number
  jack: string | null
}

export interface Step {
  key: string
  label: string
  status: 'running' | 'done' | 'failed' | 'skipped' | 'warning'
  detail?: string
  device?: string
  at: string
}

export interface DiscoveryRun {
  id: number
  seed_ip: string
  max_depth: number
  scope: string[]
  options: Record<string, any>
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  steps: Step[]
  summary: Record<string, any>
  error: string | null
  created_by: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface TopoNode {
  id: number
  label: string
  type: string
  vendor?: string
  model?: string
  ip?: string
  managed: boolean
  status: string
  location?: string
  floor?: string
  building?: string
  location_id?: number | null
  tags?: string[]
  x?: number
  y?: number
  pinned: boolean
  level: number
  infra: boolean
  degree: number
}

export interface TopoEdge {
  id: string
  a: number
  b: number
  a_port?: string
  b_port?: string
  layer: 'physical' | 'l2' | 'l3'
  sources: string[]
  speed_bps?: number
  medium?: string
  confidence: number
  manual: boolean
}

export interface Location {
  id: number
  parent_id: number | null
  kind: 'site' | 'building' | 'floor' | 'room' | 'closet' | 'area'
  name: string
  description: string | null
  level: number | null
  path: string
  device_count: number
}

export interface Jack {
  id: number
  location_id: number
  location: string
  label: string
  patch_panel_id: number | null
  patch_panel: string | null
  patch_port: number | null
  switch_device_id: number | null
  switch: string | null
  switch_interface_id: number | null
  port: string | null
  description: string | null
  current_devices: number
}

export interface Rack {
  id: number
  location_id: number
  name: string
  units: number
  description: string | null
}

export interface PatchPanel {
  id: number
  location_id: number
  rack_id: number | null
  name: string
  port_count: number
}

export interface Credential {
  id: number
  name: string
  kind: 'snmp' | 'ssh' | 'telnet'
  summary: Record<string, any>
  created_at: string
}

export interface NetEvent {
  id: number
  ts: string
  device_id: number | null
  device?: string
  kind: string
  severity: 'info' | 'warning' | 'critical'
  message: string
  detail: Record<string, any>
}

export interface Alert {
  id: number
  device_id: number | null
  device?: string
  rule: string
  subject: string
  severity: 'info' | 'warning' | 'critical'
  message: string
  opened_at: string
  resolved_at: string | null
  acknowledged: boolean
}

export interface ExploreQuery {
  intent: string
  subject: string
  types?: string[]
  vendors?: string[]
  os?: string
  location?: string
  floor?: number
  room?: string
  jack?: string
  subnet?: string
  ip?: string
  connected_to?: string
  downstream?: boolean
  medium?: string
  port_changed_days?: number
  new_days?: number
  status?: string
  text?: string
  lang: string
}

export interface Connection {
  a: string
  a_id: number
  a_port: string
  b: string
  b_id: number
  b_port: string
  medium: string
  speed_bps: number
  sources: string[]
  confidence: number
}

export interface ExploreAnswer {
  question: string
  query: ExploreQuery
  interpretation: string[]
  interpreter: string
  text: string
  count: number
  devices?: DeviceRow[]
  connections?: Connection[]
  jacks?: { id: number; label: string; location: string; patch_panel?: string; patch_port?: number; switch?: string; switch_id?: number; port?: string; seen_count?: number }[]
  notes?: string[]
  sources: string[]
  recognized: boolean
  suggestions?: string[]
}

export interface Settings {
  telnet_allowed: boolean
  default_depth: number
  default_scope: string[]
  active_fingerprinting: boolean
  max_devices: number
}
