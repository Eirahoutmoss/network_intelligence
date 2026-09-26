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
    managed              BOOLEAN NOT NULL DEFAULT FALSE,  -- polled via SNMP
    status               TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('up','down','unknown')),
    discovered_via       TEXT NOT NULL DEFAULT 'seed',
    -- derived intelligence
    device_type          TEXT NOT NULL DEFAULT 'unknown',
    device_type_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    os_name              TEXT,
    os_confidence        DOUBLE PRECISION NOT NULL DEFAULT 0,
    vendor_source        TEXT,
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
