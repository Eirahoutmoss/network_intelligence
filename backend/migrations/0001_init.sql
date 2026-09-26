-- Network Intelligence Platform — initial schema.
--
-- Data is split into three layers (see docs/architecture.md):
--   * machine-discovered facts  (devices.*, interfaces, neighbors, fdb_entries, ...)
--   * user-defined context       (device_context, device_tags, locations, jacks, ...)
--   * derived intelligence       (classification fields + evidence, topology_edges, attachments)
-- User context never overwrites discovered facts; it lives in its own tables.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------- users/auth
CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE auth_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_sessions_user ON auth_sessions(user_id);

CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    username   TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_ts ON audit_log(ts DESC);

-- ---------------------------------------------------------------- credentials
-- secret is AES-256-GCM ciphertext (see internal/credentials). Never plaintext.
CREATE TABLE credentials (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('snmp','ssh','telnet')),
    summary     JSONB NOT NULL DEFAULT '{}'::jsonb,  -- non-secret display info (version, username, port)
    secret      BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- devices
CREATE TABLE devices (
    id                   BIGSERIAL PRIMARY KEY,
    -- discovered facts
    hostname             TEXT,
    sys_name             TEXT,
    sys_descr            TEXT,
    sys_object_id        TEXT,
    sys_contact          TEXT,
    sys_location         TEXT,
    vendor               TEXT,
    model                TEXT,
    serial               TEXT,
    os_version           TEXT,
    hardware_rev         TEXT,
    mgmt_ip              INET,
    uptime_seconds       BIGINT,
    cpu_percent          DOUBLE PRECISION,
    memory_percent       DOUBLE PRECISION,
    chassis_id           TEXT,
    stp_root             TEXT,
    managed              BOOLEAN NOT NULL DEFAULT FALSE,  -- polled via SNMP
    is_router            BOOLEAN NOT NULL DEFAULT FALSE,
    is_bridge            BOOLEAN NOT NULL DEFAULT FALSE,
    is_printer           BOOLEAN NOT NULL DEFAULT FALSE,
    status               TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('up','down','unknown')),
    discovered_via       TEXT NOT NULL DEFAULT 'seed',
    -- derived intelligence
    device_type          TEXT NOT NULL DEFAULT 'unknown',
    device_type_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    os_name              TEXT,
    os_confidence        DOUBLE PRECISION NOT NULL DEFAULT 0,
    vendor_source        TEXT,
    vendor_confidence    DOUBLE PRECISION NOT NULL DEFAULT 0,
    oui_vendor           TEXT,
    random_mac           BOOLEAN NOT NULL DEFAULT FALSE,
    fingerprint          JSONB NOT NULL DEFAULT '{}'::jsonb,   -- latest endpoint observation
    fingerprinted_at     TIMESTAMPTZ,
    -- access
    snmp_credential_id   BIGINT REFERENCES credentials(id) ON DELETE SET NULL,
    ssh_credential_id    BIGINT REFERENCES credentials(id) ON DELETE SET NULL,
    telnet_credential_id BIGINT REFERENCES credentials(id) ON DELETE SET NULL,
    telnet_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    ssh_host_key         TEXT,   -- trust-on-first-use fingerprint
    -- bookkeeping
    first_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_discovered_at   TIMESTAMPTZ,
    last_polled_at       TIMESTAMPTZ,
    merged_into          BIGINT REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX devices_mgmt_ip ON devices(mgmt_ip);
CREATE INDEX devices_sys_name ON devices(lower(sys_name));
CREATE INDEX devices_type ON devices(device_type);
CREATE INDEX devices_vendor ON devices(lower(vendor));

CREATE TABLE device_addresses (
    device_id    BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip           INET NOT NULL,
    prefix_len   INT,
    if_index     INT,
    source       TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, ip)
);
CREATE INDEX device_addresses_ip ON device_addresses(ip);

CREATE TABLE device_macs (
    device_id    BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mac          MACADDR NOT NULL,
    source       TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, mac)
);
CREATE INDEX device_macs_mac ON device_macs(mac);

CREATE TABLE device_hostnames (
    device_id    BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    source       TEXT NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, name, source)
);

-- Evidence supporting derived attributes (device type, os, vendor, identity).
CREATE TABLE evidence (
    id          BIGSERIAL PRIMARY KEY,
    device_id   BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    attribute   TEXT NOT NULL,
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    detail      TEXT,
    weight      DOUBLE PRECISION NOT NULL DEFAULT 0,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_device ON evidence(device_id, attribute);

-- ---------------------------------------------------------------- interfaces (L1)
CREATE TABLE interfaces (
    id            BIGSERIAL PRIMARY KEY,
    device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index      INT NOT NULL,
    name          TEXT,
    descr         TEXT,
    alias         TEXT,
    if_type       INT,
    mtu           INT,
    speed_bps     BIGINT,
    mac           MACADDR,
    admin_status  TEXT,
    oper_status   TEXT,
    duplex        TEXT,
    medium        TEXT,
    pvid          INT,
    in_octets     NUMERIC,
    out_octets    NUMERIC,
    in_errors     NUMERIC,
    out_errors    NUMERIC,
    in_bps        DOUBLE PRECISION,
    out_bps       DOUBLE PRECISION,
    last_change_seconds BIGINT,
    is_uplink     BOOLEAN NOT NULL DEFAULT FALSE,
    stp_state     TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, if_index)
);

CREATE TABLE interface_metrics (
    interface_id BIGINT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    ts           TIMESTAMPTZ NOT NULL,
    in_bps       DOUBLE PRECISION,
    out_bps      DOUBLE PRECISION,
    in_errors    NUMERIC,
    out_errors   NUMERIC,
    PRIMARY KEY (interface_id, ts)
);

CREATE TABLE interface_vlans (
    interface_id BIGINT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    vlan_id      INT NOT NULL,
    tagged       BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (interface_id, vlan_id)
);

CREATE TABLE optics (
    interface_id BIGINT PRIMARY KEY REFERENCES interfaces(id) ON DELETE CASCADE,
    vendor       TEXT,
    part_number  TEXT,
    serial       TEXT,
    module_type  TEXT,
    wavelength_nm INT,
    rx_dbm       DOUBLE PRECISION,
    tx_dbm       DOUBLE PRECISION,
    temperature_c DOUBLE PRECISION,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE inventory_items (
    device_id    BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ent_index    INT NOT NULL,
    parent_index INT,
    class        TEXT,
    name         TEXT,
    descr        TEXT,
    model        TEXT,
    serial       TEXT,
    hw_rev       TEXT,
    fw_rev       TEXT,
    sw_rev       TEXT,
    manufacturer TEXT,
    PRIMARY KEY (device_id, ent_index)
);

CREATE TABLE sensors (
    id          BIGSERIAL PRIMARY KEY,
    device_id   BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    value       DOUBLE PRECISION,
    unit        TEXT,
    status      TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, kind, name)
);

-- ---------------------------------------------------------------- L2
CREATE TABLE neighbors (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocol            TEXT NOT NULL CHECK (protocol IN ('lldp','cdp')),
    local_interface_id  BIGINT REFERENCES interfaces(id) ON DELETE SET NULL,
    local_port          TEXT,
    remote_chassis_id   TEXT,
    remote_port_id      TEXT,
    remote_port_descr   TEXT,
    remote_sys_name     TEXT,
    remote_sys_descr    TEXT,
    remote_platform     TEXT,
    remote_mgmt_ip      INET,
    remote_capabilities TEXT[] NOT NULL DEFAULT '{}',
    remote_device_id    BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    remote_interface_id BIGINT REFERENCES interfaces(id) ON DELETE SET NULL,
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX neighbors_device ON neighbors(device_id);

CREATE TABLE vlans (
    device_id  BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    vlan_id    INT NOT NULL,
    name       TEXT,
    PRIMARY KEY (device_id, vlan_id)
);

CREATE TABLE fdb_entries (
    device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mac           MACADDR NOT NULL,
    vlan_id       INT NOT NULL DEFAULT 0,
    interface_id  BIGINT REFERENCES interfaces(id) ON DELETE CASCADE,
    status        TEXT,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, mac, vlan_id)
);
CREATE INDEX fdb_mac ON fdb_entries(mac);
CREATE INDEX fdb_interface ON fdb_entries(interface_id);

-- ---------------------------------------------------------------- L3
CREATE TABLE arp_entries (
    device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip            INET NOT NULL,
    mac           MACADDR NOT NULL,
    interface_id  BIGINT REFERENCES interfaces(id) ON DELETE SET NULL,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, ip, mac)
);
CREATE INDEX arp_mac ON arp_entries(mac);
CREATE INDEX arp_ip ON arp_entries(ip);

CREATE TABLE routes (
    device_id   BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    destination CIDR NOT NULL,
    next_hop    INET NOT NULL,
    if_index    INT,
    protocol    TEXT,
    metric      INT,
    PRIMARY KEY (device_id, destination, next_hop)
);

CREATE TABLE subnets (
    cidr        CIDR PRIMARY KEY,
    gateway_device_id BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    gateway_ip  INET,
    vlan_id     INT,
    name        TEXT,           -- user-provided label
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- derived: attachments & topology
-- Where an endpoint is physically attached (switch access port). History is kept:
-- when an endpoint moves, the old row gets ended_at set and a new row is opened.
CREATE TABLE attachments (
    id            BIGSERIAL PRIMARY KEY,
    device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    switch_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_id  BIGINT REFERENCES interfaces(id) ON DELETE CASCADE,
    port_name     TEXT,
    vlan_id       INT,
    mac           MACADDR,
    source        TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL DEFAULT 0,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at      TIMESTAMPTZ
);
CREATE INDEX attachments_device ON attachments(device_id) WHERE ended_at IS NULL;
CREATE INDEX attachments_iface ON attachments(interface_id) WHERE ended_at IS NULL;
CREATE UNIQUE INDEX attachments_current ON attachments(device_id) WHERE ended_at IS NULL;

CREATE TABLE topology_edges (
    id              BIGSERIAL PRIMARY KEY,
    a_device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    a_interface_id  BIGINT REFERENCES interfaces(id) ON DELETE SET NULL,
    a_port          TEXT,
    b_device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    b_interface_id  BIGINT REFERENCES interfaces(id) ON DELETE SET NULL,
    b_port          TEXT,
    layer           TEXT NOT NULL CHECK (layer IN ('physical','l2','l3')),
    sources         TEXT[] NOT NULL DEFAULT '{}',
    speed_bps       BIGINT,
    medium          TEXT,
    confidence      DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX topology_edges_a ON topology_edges(a_device_id);
CREATE INDEX topology_edges_b ON topology_edges(b_device_id);

-- user-defined relationships (context layer) — merged into the graph at read time
CREATE TABLE manual_links (
    id              BIGSERIAL PRIMARY KEY,
    a_device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    a_port          TEXT,
    b_device_id     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    b_port          TEXT,
    medium          TEXT,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE topology_layout (
    device_id   BIGINT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    x           DOUBLE PRECISION NOT NULL,
    y           DOUBLE PRECISION NOT NULL,
    pinned      BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- locations (user context)
CREATE TABLE locations (
    id          BIGSERIAL PRIMARY KEY,
    parent_id   BIGINT REFERENCES locations(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('site','building','floor','room','closet','area')),
    name        TEXT NOT NULL,
    description TEXT,
    level       INT,          -- floor number when kind = floor
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX locations_parent ON locations(parent_id);

CREATE TABLE racks (
    id          BIGSERIAL PRIMARY KEY,
    location_id BIGINT NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    units       INT NOT NULL DEFAULT 42,
    description TEXT
);

CREATE TABLE patch_panels (
    id          BIGSERIAL PRIMARY KEY,
    location_id BIGINT NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
    rack_id     BIGINT REFERENCES racks(id) ON DELETE SET NULL,
    name        TEXT NOT NULL,
    port_count  INT NOT NULL DEFAULT 24
);

-- Wall jack / network socket, and its physical path to a switch port.
CREATE TABLE network_jacks (
    id                  BIGSERIAL PRIMARY KEY,
    location_id         BIGINT NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
    label               TEXT NOT NULL,
    patch_panel_id      BIGINT REFERENCES patch_panels(id) ON DELETE SET NULL,
    patch_port          INT,
    switch_device_id    BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    switch_interface_id BIGINT REFERENCES interfaces(id) ON DELETE SET NULL,
    description         TEXT,
    UNIQUE (location_id, label)
);

CREATE TABLE device_context (
    device_id          BIGINT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    display_name       TEXT,
    description        TEXT,
    department         TEXT,
    device_type_override TEXT,
    location_id        BIGINT REFERENCES locations(id) ON DELETE SET NULL,
    rack_id            BIGINT REFERENCES racks(id) ON DELETE SET NULL,
    rack_unit          INT,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_tags (
    device_id  BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    PRIMARY KEY (device_id, tag)
);

-- ---------------------------------------------------------------- discovery
CREATE TABLE discovery_runs (
    id           BIGSERIAL PRIMARY KEY,
    seed_ip      INET NOT NULL,
    credential_id BIGINT REFERENCES credentials(id) ON DELETE SET NULL,
    max_depth    INT NOT NULL DEFAULT 1,
    scope        CIDR[] NOT NULL DEFAULT '{}',
    options      JSONB NOT NULL DEFAULT '{}'::jsonb,
    status       TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled')),
    steps        JSONB NOT NULL DEFAULT '[]'::jsonb,
    summary      JSONB NOT NULL DEFAULT '{}'::jsonb,
    error        TEXT,
    created_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ
);

CREATE TABLE poll_runs (
    id          BIGSERIAL PRIMARY KEY,
    device_id   BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms INT,
    ok          BOOLEAN NOT NULL,
    error       TEXT
);
CREATE INDEX poll_runs_device ON poll_runs(device_id, started_at DESC);

-- ---------------------------------------------------------------- events/alerts
CREATE TABLE events (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_id  BIGINT REFERENCES devices(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
    message    TEXT NOT NULL,
    detail     JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX events_ts ON events(ts DESC);
CREATE INDEX events_device ON events(device_id, ts DESC);

CREATE TABLE alerts (
    id           BIGSERIAL PRIMARY KEY,
    device_id    BIGINT REFERENCES devices(id) ON DELETE CASCADE,
    rule         TEXT NOT NULL,
    subject      TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
    message      TEXT NOT NULL,
    opened_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX alerts_open ON alerts(device_id, rule, subject) WHERE resolved_at IS NULL;

-- ---------------------------------------------------------------- cli
CREATE TABLE cli_sessions (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    username    TEXT,
    device_id   BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    protocol    TEXT NOT NULL,
    remote_addr TEXT,
    client_addr TEXT,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    end_reason  TEXT,
    bytes_in    BIGINT NOT NULL DEFAULT 0,
    bytes_out   BIGINT NOT NULL DEFAULT 0,
    transcript  BYTEA
);

-- ---------------------------------------------------------------- settings
CREATE TABLE settings (
    key    TEXT PRIMARY KEY,
    value  JSONB NOT NULL
);

-- ---------------------------------------------------------------- views
-- Full path and building/floor/room names for each location.
CREATE VIEW location_paths AS
WITH RECURSIVE t AS (
    SELECT id, parent_id, kind, name, level,
           name::text AS path,
           CASE WHEN kind = 'building' THEN name END AS building,
           CASE WHEN kind = 'floor' THEN name END AS floor,
           CASE WHEN kind = 'floor' THEN level END AS floor_level,
           CASE WHEN kind IN ('room','closet','area') THEN name END AS room,
           ARRAY[id] AS ancestors
    FROM locations WHERE parent_id IS NULL
    UNION ALL
    SELECT l.id, l.parent_id, l.kind, l.name, l.level,
           t.path || ' / ' || l.name,
           COALESCE(CASE WHEN l.kind = 'building' THEN l.name END, t.building),
           COALESCE(CASE WHEN l.kind = 'floor' THEN l.name END, t.floor),
           COALESCE(CASE WHEN l.kind = 'floor' THEN l.level END, t.floor_level),
           COALESCE(CASE WHEN l.kind IN ('room','closet','area') THEN l.name END, t.room),
           t.ancestors || l.id
    FROM locations l JOIN t ON l.parent_id = t.id
)
SELECT * FROM t;

-- One row per device with the display-ready fields shared by the device list,
-- explorer and reports. Effective location is inferred when the user has not
-- set one: wall jack mapping first, then the location of the attached switch.
CREATE VIEW device_view AS
SELECT d.id,
       COALESCE(c.display_name, d.sys_name, d.hostname, host(d.mgmt_ip), ip.ip, mac.mac, '#' || d.id) AS name,
       d.hostname, d.sys_name, c.display_name,
       COALESCE(c.device_type_override, d.device_type) AS device_type,
       CASE WHEN c.device_type_override IS NOT NULL THEN 1 ELSE d.device_type_confidence END AS device_type_confidence,
       c.device_type_override IS NOT NULL AS type_overridden,
       COALESCE(d.vendor, d.oui_vendor) AS vendor, d.model, d.serial, d.os_name, d.os_confidence, d.os_version,
       COALESCE(host(d.mgmt_ip), ip.ip) AS ip, mac.mac, d.managed, d.status, d.discovered_via,
       d.first_seen, d.last_seen, d.uptime_seconds, d.cpu_percent, d.memory_percent,
       att.switch_id, COALESCE(swc.display_name, sw.sys_name) AS switch_name, att.interface_id AS switch_interface_id,
       att.port_name AS switch_port, att.vlan_id, att.confidence AS attachment_confidence, att.source AS attachment_source,
       j.id AS jack_id, j.label AS jack,
       COALESCE(c.location_id, j.location_id, swc.location_id) AS location_id,
       CASE WHEN c.location_id IS NOT NULL THEN 'user' WHEN j.location_id IS NOT NULL THEN 'jack'
            WHEN swc.location_id IS NOT NULL THEN 'switch' END AS location_source,
       lp.path AS location_path, lp.building, lp.floor, lp.floor_level, lp.room,
       c.description, c.department,
       COALESCE((SELECT array_agg(t.tag ORDER BY t.tag) FROM device_tags t WHERE t.device_id = d.id), '{}') AS tags
FROM devices d
LEFT JOIN device_context c ON c.device_id = d.id
LEFT JOIN LATERAL (SELECT host(a.ip) AS ip FROM device_addresses a WHERE a.device_id = d.id
                   ORDER BY (a.source = 'snmp') DESC, a.last_seen DESC LIMIT 1) ip ON true
LEFT JOIN LATERAL (SELECT m.mac::text AS mac FROM device_macs m WHERE m.device_id = d.id
                   ORDER BY (m.source = 'snmp') DESC, m.first_seen LIMIT 1) mac ON true
LEFT JOIN attachments att ON att.device_id = d.id AND att.ended_at IS NULL
LEFT JOIN devices sw ON sw.id = att.switch_id
LEFT JOIN device_context swc ON swc.device_id = att.switch_id
LEFT JOIN network_jacks j ON j.switch_interface_id = att.interface_id
LEFT JOIN location_paths lp ON lp.id = COALESCE(c.location_id, j.location_id, swc.location_id);
