# HTTP API

All endpoints are under `/api` and exchange JSON. Authenticate with `POST /api/auth/login`
(sets the `nexus_session` cookie) or send `Authorization: Bearer <token>`. Every
state-changing request made with the cookie must carry `X-Requested-With: nexus`.

Errors: `{"error": "message"}` with an appropriate status (400 validation, 401
unauthenticated, 403 forbidden, 404, 409 conflict, 500).

## Public

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | `{status, database, db_latency_ms, version}` |
| GET | `/metrics` | Prometheus metrics |
| POST | `/api/auth/login` | `{username, password}` → `{user}` + cookie |
| POST | `/api/auth/logout` | |

## Viewer

| Method | Path | Description |
|---|---|---|
| GET | `/api/auth/me` · `/api/info` | Current user · version, simulator and LLM flags |
| GET | `/api/dashboard` | Totals, breakdowns, recent events/runs, busiest ports |
| GET | `/api/devices` | Query: `q, type, vendor, os, status, managed, location_id, switch_id, subnet, vlan, tag, new_days, moved_days, sort, limit, offset` → `{devices, total}` |
| GET | `/api/devices/{id}` | Detail: facts, addresses, MACs, names, evidence, context, port history, sensors, inventory, fingerprint, access, stats |
| GET | `/api/devices/{id}/interfaces` · `/neighbors` · `/endpoints` · `/events` | |
| GET | `/api/devices/{id}/tables/{fdb,arp,routes,vlans,raw}` | Raw collected tables |
| GET | `/api/interfaces/{id}/metrics?hours=24` | Traffic rate history |
| GET | `/api/topology` | Query: `layer, infra_only, location_id, focus` → `{nodes, edges}` |
| GET | `/api/connections` | Query: `medium, layer, infra` |
| POST | `/api/explore` | `{question}` → answer (text, interpretation, devices/connections/jacks, notes, sources) |
| POST | `/api/explore/query` | Structured query (`types, vendors, os, location, floor, room, jack, subnet, ip, connected_to, downstream, medium, port_changed_days, new_days, status, text, lang`) |
| GET | `/api/locations` · `/api/racks` · `/api/patch-panels` · `/api/jacks?location_id=` | |
| GET | `/api/events?device_id=&limit=` · `/api/alerts?all=true` | |
| GET | `/api/subnets` · `/api/vlans` | |
| GET | `/api/discovery/runs` · `/api/discovery/runs/{id}` | |
| GET | `/api/discovery/runs/{id}/stream` | Server-Sent Events: `snapshot`, then `update` (`{step}` or `{status, summary}`) |
| GET | `/api/discovery/defaults?ip=` | Default scope/depth for a seed |
| GET | `/api/reports/summary` · `/api/reports/inventory.csv` | |

## Operator

| Method | Path | Description |
|---|---|---|
| POST | `/api/devices` | **Add Device**: `{ip, snmp: {username, password} \| {community}, options?: {max_depth, scope[], active_fingerprint, try_all_credentials, max_devices}, ssh?: {username, password}}` or `{ip, credential_id}` → `202 {run_id}` |
| POST | `/api/discovery/refresh` | Re-collect all managed devices |
| POST | `/api/discovery/runs/{id}/cancel` | |
| GET | `/api/credentials` | Non-secret summaries |
| PUT | `/api/devices/{id}/context` | `{display_name, description, department, device_type_override, location_id, rack_id, rack_unit, tags[]}` |
| PUT | `/api/devices/{id}/access` | `{ssh_credential_id, telnet_credential_id, telnet_enabled}` (Telnet: admin) |
| POST | `/api/devices/assign-location` | `{device_ids[], location_id}` |
| POST/PUT/DELETE | `/api/locations[/{id}]` | `{kind, name, parent_id, description, level}` |
| POST | `/api/locations/import-syslocation` | Build locations from SNMP sysLocation |
| POST/DELETE | `/api/racks`, `/api/patch-panels` | |
| POST/PUT/DELETE | `/api/jacks[/{id}]` | `{location_id, label, patch_panel_id, patch_port, switch_interface_id, description}` |
| PUT/DELETE | `/api/topology/layout` | Save `{positions:[{id,x,y}]}` / reset |
| POST/DELETE | `/api/manual-links[/{id}]` | `{a_device_id, a_port, b_device_id, b_port, medium, description}` |
| POST | `/api/alerts/{id}/ack` | |
| GET (WebSocket) | `/api/devices/{id}/cli?protocol=ssh\|telnet&cols=&rows=` | Client → `{"type":"input","data":"…"}`, `{"type":"resize","cols":…,"rows":…}`; server → `{"type":"output","data":base64}`, `status`, `error`, `closed` |

## Admin

| Method | Path | Description |
|---|---|---|
| POST/DELETE | `/api/credentials[/{id}]` | `{kind: snmp\|ssh\|telnet, name, snmp: {...} \| login: {username, password, private_key, port}}` |
| DELETE | `/api/devices/{id}` · `/api/devices/{id}/ssh-host-key` | |
| GET/POST/PUT/DELETE | `/api/users[/{id}]` | `{username, password, role}` / `{role, disabled, password?}` |
| GET | `/api/audit` | |
| GET | `/api/cli-sessions` · `/api/cli-sessions/{id}/transcript` | |
| POST | `/api/cli-sessions/{id}/terminate` | |
| GET/PUT | `/api/settings` | `{telnet_allowed, default_depth, default_scope[], active_fingerprinting, max_devices}` |
