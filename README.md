# snmp-backend

An SNMP metrics backend: FastAPI polls cpu, ram, disk capacity, disk throughput
and IOPS, and network from a client-controlled set of machines every 5 seconds,
stores the samples in TimescaleDB, and streams them live over SSE. Docker Compose
runs the API and database locally, with configuration and credentials in `.env`.

## Design

**OpenStack is the only source of truth for machine facts.** The database stores
identity, polling address and how to authenticate, and nothing else: MAC, IPv4,
the client's own label, an enabled flag, a credential reference. Server id,
tenant, user, flavor and its specs are looked up per request and never persisted,
so there is no second copy to drift.

**MAC is identity; IPv4 is a polling address.** A client registers a machine by
IPv4 and the backend resolves the MAC from OpenStack. Each collection cycle
re-reads the address from the lookup, so a re-IP'd server keeps being polled.
Deleting a MAC deletes its history.

**Machines outside OpenStack are registered with their MAC.** An address the
fleet does not know has no MAC to resolve, so the client supplies one and the
row is flagged `external`: no OpenStack details on reads, and the collector
leaves its address alone — `PATCH {ipv4}` is how an external machine moves, and
it is rejected for a managed one, whose address the next tick would overwrite. A
MAC supplied for an address OpenStack *does* know must agree with it. The flag
is stored rather than inferred from a missing lookup record, because "never was
in OpenStack" and "deleted from OpenStack after registration" are different
answers; if such a machine later turns up in the fleet — registered external
during a lookup outage, or imported since — the next tick clears the flag.

**Metrics are one column each, and every one is nullable.** A sample missing a
metric — an SNMP walk that failed, a rate with no previous reading behind it, a
machine polled before the metric existed — stores NULL, and aggregates skip it
rather than erroring or averaging in a zero. Adding a metric now costs a
migration; what it buys is [a twentieth of the
storage](#why-the-metrics-table-is-wide) and continuous aggregates, which the
jsonb shape could not have at all.

**SNMP credentials are rows, shared, and encrypted.** v2c and v3 are both
credential profiles a machine is bound to, so there is one code path in the
sampler and "which credential is this machine using" always has an answer.
Sharing is what makes rotation feasible and what makes binding dangerous, so
binding is a scope of its own — see [SNMP credentials](#snmp-credentials).

**Both external systems are simulated, behind interfaces.** `SNMP_SIMULATE` and
`OPENSTACK_SIMULATE` pick a fake sampler and a fake fleet. The real OpenStack
adapter is deliberately read-only: it lists Nova servers across projects,
Keystone projects/users and Neutron ports/subnets, then translates those
resources into the same `ServerInfo` returned by the simulator. It issues no
create, update or delete operation. The simulated agent sizes each host from its
OpenStack flavor, so an `m1.small` reports 1 core and 2 GiB rather than
contradicting itself.

No network is singled out. Every network a server is attached to is walked in
Nova's own order and the first *fixed* IPv4 carrying a MAC is taken — floating
addresses are skipped, because only a fixed address belongs to the port whose MAC
the collector joins on. The trade for not naming a network is that a server
rewired onto a new network ahead of its old one is tracked at the new address.

Nova's address entry supplies the MAC and the IPv4 but names no subnet, so
`subnet_name` comes from the Neutron port that owns the address — two fleet-wide
listings per cache refresh, not two per server. It is a label rather than a join
key, so a Neutron the credential cannot read costs the label alone: the server is
still returned, with `subnet_name` null.

The adapter's code path is read-only, but a credential's authority is still a
cloud policy decision. The user's roles should permit only the required Nova,
Keystone and Neutron `GET` operations. Those permissions must also allow Nova's
all-project server list, Keystone's project/user lists and Neutron's cloud-wide
port and subnet lists; a normal project-scoped reader often cannot see that
inventory.

## Layout

| Path | Purpose |
| --- | --- |
| `src/app/main.py` | App factory and lifespan: migrations, engine, admin bootstrap, collector |
| `src/app/config.py` | `pydantic-settings`; env wins over `.env` |
| `src/app/db/tables.py` | Every table as SQLAlchemy sees it — what Alembic diffs against |
| `src/app/db/migrations/` | Alembic revisions. Inside the package, so they ship in the image |
| `src/app/db/migrate.py` | `alembic upgrade head` with retries and an advisory lock. Also `python -m app.db.migrate` |
| `src/app/db/policies.py` | Chunk interval, compression, retention and rollup refresh: settings, not schema, so re-applied every boot |
| `src/app/db/rollups.py` | The continuous aggregate spec, and which source a range is read from |
| `src/app/db/pool.py` | SQLAlchemy engine over psycopg2 + threadpool query/session helpers |
| `src/app/db/{machines,metrics,credentials}.py` | Fleet, metric and credential repositories: hand-written SQL, no ORM |
| `src/app/db/reencrypt.py` | `python -m app.db.reencrypt` — moves stored credentials onto the active key |
| `src/app/db/{users,roles,tokens}.py` | Identity repositories: ORM, one transaction per function |
| `src/app/security/scopes.py` | The permission vocabulary. Fixed in code, no table |
| `src/app/security/crypto.py` | AES-256-GCM over the credential key ring; the only module that opens a secret |
| `src/app/api/security.py` | Bearer + scope checking, and the SSE stream tickets |
| `src/app/services/auth.py` | Argon2 hashing and JWT minting |
| `src/app/services/bootstrap.py` | Ensures the admin role, account and `default-v2c` credential exist |
| `src/app/services/credentials.py` | Decrypted-credential cache, keyed on `(id, secret_version)` |
| `src/app/services/openstack/` | `OpenStackLookup` protocol, TTL cache, read-only SDK adapter and simulated fleet |
| `src/app/services/snmp/` | `SnmpSampler` protocol, pysnmp backend, simulator |
| `src/app/services/snmp/flatten.py` | The only place that maps a nested reading onto columns, and back |
| `src/app/services/collector.py` | The polling loop, and the last full reading per machine |
| `src/app/services/bus.py` | In-process pub/sub feeding SSE |
| `src/app/api/routers/` | health, auth, users, roles, machines, credentials, metrics, stream, admin |
| `alembic.ini` | Host CLI only; the app builds an equivalent config in code |
| `.env.example` | Every setting with defaults; `.env` is git- and docker-ignored |
| `compose.yaml` | Local API, TimescaleDB, and profile-gated SNMP test agents |
| `scripts/seed_dev.py` | Registers the simulated fleet, binds credentials, and prints login tokens |
| `Makefile` | `up`, `seed`, `psql`, `logs`, `reencrypt`, `clean` for the Compose stack |

## Data model

Owned by Alembic. Revision `0001` creates the fleet tables, `0002` the identity
ones and `0003` the SNMP credentials; the app runs `alembic upgrade head` on
startup.

```sql
CREATE TABLE machines (
    mac        macaddr PRIMARY KEY,      -- identity: from OpenStack, or client-supplied
    ipv4       inet    NOT NULL UNIQUE,  -- what the collector polls
    label      text,                     -- the client's own annotation
    enabled    boolean NOT NULL DEFAULT true,
    external   boolean NOT NULL DEFAULT false,  -- not an OpenStack server
    credential_id uuid REFERENCES snmp_credentials (id) ON DELETE RESTRICT,
    ...
);

CREATE TABLE snmp_credentials (
    id             uuid PRIMARY KEY,
    name           text NOT NULL UNIQUE,
    snmp_version   text NOT NULL,        -- '2c' | '3'
    username       text,                 -- v3 securityName
    security_level text,                 -- noAuthNoPriv | authNoPriv | authPriv
    auth_protocol  text,                 -- MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
    priv_protocol  text,                 -- DES | 3DES | AES128 | AES192 | AES256
    secret         bytea NOT NULL,       -- nonce ‖ AES-256-GCM(passphrases)
    key_id         text  NOT NULL,       -- which ring key sealed it
    secret_version int   NOT NULL DEFAULT 1,
    fingerprint    text  NOT NULL,       -- keyed HMAC, so a client can compare without reading
    ...
);

CREATE TABLE metrics (
    ts   timestamptz NOT NULL,
    mac  macaddr     NOT NULL REFERENCES machines (mac) ON DELETE CASCADE,

    cpu_usage_pct         real,      cpu_cores           smallint,
    ram_total_bytes       bigint,    ram_used_bytes      bigint,
    ram_used_pct          real,      ram_available_bytes bigint,
    disk_root_total_bytes bigint,    disk_root_used_bytes bigint,
    disk_root_used_pct    real,      disk_max_used_pct    real,
    dio_read_bps  double precision,  dio_write_bps double precision,
    dio_read_iops real,              dio_write_iops real,
    dio_read_bytes bigint,           dio_write_bytes bigint,
    dio_reads      bigint,           dio_writes      bigint,
    dio_busy_pct   real,
    net_rx_bps double precision,     net_tx_bps double precision,
    net_rx_bytes bigint,             net_tx_bytes bigint,
    net_rx_util_pct real,            net_tx_util_pct real,
    net_speed_bps bigint,            interval_ms   integer
);
SELECT create_hypertable('metrics', by_range('ts'));
```

One column per metric, all nullable, and no jsonb. Revision `0004` made that
change; see [Why the metrics table is wide](#why-the-metrics-table-is-wide) for
the measurements behind it and what stopped being stored.

Deliberately *not* loaded through `/docker-entrypoint-initdb.d`: that only runs
against an empty data directory, so it could never be evolved. Migrations run on
every startup instead, under a Postgres advisory lock so replicas starting
together do not race. `DB_AUTO_MIGRATE=false` hands the schema to something else
— a separate process running `python -m app.db.migrate`, say.

Revision `0001` no-ops on a database that already has `machines`, so an installation
deployed before Alembic is adopted by the same `upgrade head` that builds a fresh
one, with no manual `alembic stamp`.

The identity tables are `users`, `roles`, `role_scopes`, `user_roles` and
`refresh_tokens` — see [Authentication](#authentication). `snmp_credentials` has
its own section: [SNMP credentials](#snmp-credentials).

Revision `0003` creates the credential table but does not populate it. Seeding
needs the encryption key ring, and Alembic deliberately loads only
`DatabaseSettings` — so a migration process never has to be handed one. The
`default-v2c` row is written by `app.services.bootstrap` on the first boot that
finds none.

The FK is what makes "delete the MAC, delete its history" one statement. A
hypertable may reference a regular table; the cascade touches every chunk, which
is fine at this scale — time-ranged purges use `drop_chunks` instead.

`app.services.snmp.flatten` maps the sampler's nested reading onto those
columns and back. A reading, before flattening, looks like:

```json
{"cpu":  {"usage_percent": 22.93, "cores": 1},
 "ram":  {"total_bytes": 2147483648, "used_bytes": 727130208, "used_percent": 33.86,
          "available_bytes": 1420353440, "buffers_bytes": 35889152, "cached_bytes": 1121976320},
 "disk": [{"mount": "/", "total_bytes": 21474836480, "used_bytes": 8967258924, "used_percent": 41.76}],
 "disk_io": {"read_bps": 112487038.9, "write_bps": 45507872.5,
             "read_iops": 6865.7, "write_iops": 11110.3,
             "read_bytes": 1450273321378, "write_bytes": 1853005660426,
             "reads": 173272109, "writes": 193994381,
             "interval_seconds": 4.998,
             "devices": [{"device": "vda",
                          "read_bps": 112487038.9, "write_bps": 45507872.5,
                          "read_iops": 6865.7, "write_iops": 11110.3,
                          "read_bytes": 1450273321378, "write_bytes": 1853005660426,
                          "reads": 173272109, "writes": 193994381,
                          "busy_percent_1min": 30.14, "counted": true}]},
 "network": {"rx_bps": 812344.5, "tx_bps": 1904771.2,
             "rx_bytes": 402653184000, "tx_bytes": 915678412000,
             "interval_seconds": 5.02,
             "interfaces": [{"name": "eth0", "rx_bps": 812344.5, "tx_bps": 1904771.2,
                             "rx_bytes": 402653184000, "tx_bytes": 915678412000,
                             "speed_bps": 1000000000,
                             "rx_util_percent": 0.65, "tx_util_percent": 1.52}]}}
```

The three arrays — `disk`, `disk_io.devices` and `network.interfaces` — reach
subscribers over SSE and `GET /metrics/latest`, and are **not** stored. What is
kept from them is the root filesystem, the fullest real filesystem, and totals
over the machine's physical interfaces and counted block devices. A sample read
back out of the database therefore comes back with `disk` holding root alone and
no `devices` or `interfaces` keys, in the same nested shape otherwise.

`ram.used_bytes` is not the agent's own figure. `hrStorageUsed` for physical
memory is `MemTotal - MemFree`, which counts the page cache as used and therefore
reads as ~95% on any host that has been up long enough to fill it. The sample
reports `total - MemAvailable` instead — the same number `free` prints under
"used" — and carries `available_bytes`, `buffers_bytes` and `cached_bytes`
alongside so the raw reading can be reconstructed. Agents too old to publish an
`Available memory` row fall back to subtracting buffers and cache, and agents
that publish neither keep the raw figure.

Every rate here is one SNMP does not report: agents expose cumulative counters,
so `rx_bps`, `read_bps`, `read_iops` and the rest are derived from the delta
against the previous sample of that machine. Throughput is **bytes** per second
and IOPS is **operations** per second. They are null on the first sample after a
restart, and on a counter that reset in between — the raw counters are stored
alongside so any window can be recomputed from history. Loopback and down
interfaces are excluded.

### Disk capacity vs disk I/O

`disk` and `disk_io` are separate keys because they are indexed differently and
nothing joins them. Capacity comes from `hrStorageTable`, one row per **mount
point**; throughput comes from `diskIOTable`, one row per **block device**. On
LVM, RAID or any multi-mount device the mapping between the two is many-to-many,
so folding them into one array would mean inventing a device for each mount.

The kernel reports both a device-mapper device and the disk underneath it, and
both a partition and its whole disk. Summing every row would therefore count the
same I/O two or three times, so the host totals sum only the devices marked
`counted`; the others still appear in `devices` with their own rates.

`busy_percent_1min` is `diskIOLA1`, which the agent averages over a minute. It is
named for what it is: at a five second interval it lags the rates beside it by
design.

## Configuring an agent

The stock Debian/Ubuntu `snmpd.conf` exposes `system` and `hrSystem` and nothing
else, so a machine added to the fleet without touching it answers every walk with
an empty result — which reaches the log as `no HOST-RESOURCES-MIB rows`, not as a
permission error. Replace the `systemonly` view and the `rocommunity` lines that
reference it with:

```
view   fleet  included   .1.3.6.1.2.1.1            # system
view   fleet  included   .1.3.6.1.2.1.2            # IF-MIB ifTable
view   fleet  included   .1.3.6.1.2.1.25           # HOST-RESOURCES-MIB
view   fleet  included   .1.3.6.1.2.1.31           # IF-MIB ifXTable
view   fleet  included   .1.3.6.1.4.1.2021.13.15   # UCD DISKIO-MIB

rocommunity  public default -V fleet
```

Two things that file will punish: a trailing `#` comment on a `view` line is
parsed as the view's mask (`Error: invalid MASK`, and the line is dropped), and
appending the new lines without deleting the old ones changes nothing, because
the first `rocommunity` matching a community name wins. `snmpd` starts anyway
when a line fails to parse, so check `systemctl status snmpd` for `Error:` rather
than trusting "active (running)".

`hrProcessorLoad` is empty for the first few seconds after a restart — net-snmp
needs two reads of `/proc/stat` before it can report a load — so verify with a
walk taken a moment later, not immediately.

### SNMPv3 on the agent

`rocommunity` is v2c, and v2c sends its community string in cleartext on every
request. For v3, create the user and grant it the same view:

```
# in /var/lib/net-snmp/snmpd.conf, with snmpd stopped.
# Consumed on first start: snmpd hashes the passphrases into the file and the
# line is meant to be deleted afterwards.
createUser  fleetmon SHA-256 "auth-passphrase" AES-128 "priv-passphrase"

# in /etc/snmp/snmpd.conf
rouser      fleetmon authPriv -V fleet
```

SHA-2 and AES-192/256 need net-snmp 5.8 or newer; 5.7 and earlier offer only
MD5/SHA-1 and DES/AES-128. The API refuses MD5, DES and `noAuthNoPriv` on
create unless the payload carries `"allow_weak": true`, which is the escape
hatch for agents that genuinely support nothing better.

Verify from the agent itself before blaming the collector:

```bash
snmpget -v3 -u fleetmon -l authPriv \
  -a SHA-256 -A auth-passphrase \
  -x AES-128 -X priv-passphrase \
  127.0.0.1 1.3.6.1.2.1.1.1.0
```

`compose.yaml` has an `snmpd` service under the `snmp` profile that is
exactly this, for testing without a real host:
`docker compose --profile snmp up -d snmpd`.

Disk I/O additionally needs an `snmpd` built with the `ucd-snmp/diskio` module,
present in the Debian, Ubuntu and RHEL packages. Without it that walk returns
nothing and the `disk_io` key is dropped from the sample; cpu, ram, disk and
network are unaffected. `SNMP_DISKIO_ENABLED=false` skips the walk entirely for
fleets that will never serve it.

### Response size and MTU

`SNMP_MAX_REPETITIONS` decides how many rows an agent packs into one GETBULK
reply, and the ceiling on it is the path's, not SNMP's: a reply larger than the
smallest MTU between collector and agent is fragmented, and any hop that drops
fragments — a tunnel, a NAT out of a VM — turns that into a walk that simply
times out. Polling over Tailscale (1280-byte MTU) from a container, 25 rows of
`hrStorageDescr` on a container host is already past the line, while 10 is not:
the mount paths are long and it is the bytes, not the row count, that decide.

Because that threshold is a property of the data as much as the path, the
sampler does not rely on the setting being right. A walk that times out is
retried with the bulk size halved, and the working value is remembered per
address, so the cost is paid once instead of every tick. It is not raised again
while the process lives; a restart re-reads the configured value.

## API

Everything except the three health endpoints needs a bearer token carrying the
scope in the third column. See [Authentication](#authentication).

| Method | Path | Scope | Notes |
| --- | --- | --- | --- |
| GET | `/` | — | service info and which backends are simulated |
| GET | `/healthz` | — | no dependencies — backs liveness |
| GET | `/readyz` | — | queries Postgres — backs readiness |
| POST | `/auth/login` | — | form-encoded OAuth2 password grant ⇒ access + refresh token; throttled, 429 with `Retry-After` |
| POST | `/auth/refresh` | — | rotates the refresh token; replaying one revokes the whole chain |
| POST | `/auth/logout` | any | revokes the presented refresh token |
| GET | `/auth/me` | any | your account, roles and effective scopes |
| PATCH | `/auth/me/password` | any | needs the current password, and a different new one; ends your other sessions |
| POST | `/auth/stream-ticket` | `metrics:read` | single-use credential for `EventSource` |
| GET | `/scopes` | `roles:read` | the fixed catalogue, for building a role editor |
| GET/POST | `/roles` | `roles:read` / `roles:write` | 422 on an unknown scope name |
| GET/PATCH/DELETE | `/roles/{name}` | `roles:read` / `roles:write` | 409 on the built-in `admin` role or one still granted |
| PUT | `/roles/{name}/scopes` | `roles:write` | replace a role's scopes |
| GET/POST | `/users` | `users:read` / `users:write` | |
| GET/PATCH/DELETE | `/users/{id}` | `users:read` / `users:write` | `PATCH {is_active}` |
| PUT | `/users/{id}/roles` | `users:write` | replace a user's roles |
| PUT | `/users/{id}/password` | `users:write` | administrative reset; ends that user's sessions; 422 if unchanged |
| POST | `/machines` | `machines:write` | `{ipv4, mac?, label?}`; `mac` required — and only accepted — for an address OpenStack does not know; 404 without it, 409 if it disagrees with OpenStack or is already registered |
| GET | `/machines` | `machines:read` | our rows enriched with server id, tenant, user, flavor + specs; `external` marks the machines that have none |
| GET/PATCH/DELETE | `/machines/{mac}` | `machines:read` / `machines:write` | `PATCH {label?, enabled?, ipv4?}` — `ipv4` on external machines only, and only while no credential is bound; 409 otherwise. `DELETE` cascades the history |
| GET/POST | `/snmp-credentials` | `credentials:read` / `credentials:write` | reusable SNMP profiles. **No response ever contains a secret** — see [SNMP credentials](#snmp-credentials) |
| GET/PATCH/DELETE | `/snmp-credentials/{id}` | `credentials:read` / `credentials:write` | `PATCH` of any USM field takes the whole shape and bumps `secret_version`; `DELETE` is 409 while machines are bound |
| PUT/DELETE | `/machines/{mac}/snmp-credential` | `credentials:write` | bind / unbind. Deliberately **not** a field on `PATCH /machines/{mac}` |
| POST | `/machines/{mac}/snmp-credential/test` | `credentials:write` | poll this machine once. Takes no address — `{credential?}` to dry-run an unsaved one |
| GET | `/metrics` | `metrics:read` | `?mac=&since=&limit=` — repeat `mac` to filter on several |
| GET | `/metrics/latest` | `metrics:read` | most recent sample per machine |
| GET | `/metrics/stats` | `metrics:read` | `?bucket=1 minute&hours=1&mac=` — `time_bucket`, read from the raw table or a rollup depending on the range |
| GET | `/metrics/counts` | `metrics:read` | rows and latest sample per machine |
| GET | `/metrics/stream` | `metrics:read` | SSE firehose, `?mac=` to filter |
| GET | `/machines/{mac}/metrics/stream` | `metrics:read` | SSE for one machine |
| DELETE | `/machines/{mac}/metrics` | `metrics:write` | purge one machine's history, `?before=` for a range |
| DELETE | `/metrics` | `metrics:write` | purge everything; **requires `?confirm=true`**. `?before=` drops whole chunks instead |
| GET | `/admin/collector` | `admin:read` | loop health and per-machine ok/fail counts |
| POST | `/admin/collector/tick` | `admin:write` | run one round now instead of waiting; 409 if one is already running |
| GET | `/admin/openstack/cache` | `admin:read` | ttl, age, hits, misses, refreshes |
| GET | `/admin/openstack/servers` | `admin:read` | the fleet as cached — the registerable addresses |
| POST | `/admin/openstack/cache/flush` | `admin:write` | drop the cache; next read repopulates |

Streaming is a side channel: samples are written to TimescaleDB first and
published second, so subscribing changes nothing about what is stored, and events
arrive at the collector's cadence rather than on demand. The bus is per-process,
so with more than one process a client only sees what its process collected.

## SNMP credentials

How the collector authenticates to an agent is a row, not a setting. A
credential is a named profile and machines are *bound* to one; several machines
normally share a profile, because a fleet is usually polled with one or two
credentials and re-entering a passphrase per host is how passphrases end up
never being rotated.

There is no fallback. A machine with no credential bound is not polled, and says
so per machine in `GET /admin/collector`:

```json
{"mac": "aa:bb:cc:dd:ee:01", "credential": null, "ok_count": 0,
 "last_error": "no credential bound: PUT /machines/{mac}/snmp-credential"}
```

Creating and binding one:

```bash
tok=$(make -s token)

curl -fsS -X POST localhost:8000/snmp-credentials \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"name":"fleet-v3","snmp_version":"3","username":"fleetmon",
       "security_level":"authPriv",
       "auth_protocol":"SHA256","auth_passphrase":"auth-passphrase",
       "priv_protocol":"AES128","priv_passphrase":"priv-passphrase"}'

curl -fsS -X PUT localhost:8000/machines/aa:bb:cc:00:00:01/snmp-credential \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"credential_id":"<id from above>"}'

# poll it once, now, instead of waiting for a tick
curl -fsS -X POST localhost:8000/machines/aa:bb:cc:00:00:01/snmp-credential/test \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d '{}'
```

A failing test names the reason without echoing the secret — `Wrong SNMP PDU
digest` for a bad passphrase, `Unknown USM user` for a bad `username`. When
`SNMP_SIMULATE=true` the result carries `"simulated": true`, because the
simulator authenticates to nothing and would otherwise report every credential
as working.

### Why binding has its own scope

Sharing a credential is ordinary; what it changes is the blast radius of
pointing one somewhere. Binding decides which host the collector will
authenticate to with a secret the whole fleet depends on, and an SNMPv3 exchange
captured by a hostile agent can be attacked offline for the passphrase.

So registering a machine and aiming a credential at it are split across two
scopes. `machines:write` can register a machine at any address — that is cheap
and reversible. `credentials:write` is what binds:

| Action | Scope | |
| --- | --- | --- |
| `POST /machines` at any address | `machines:write` | allowed |
| `PUT /machines/{mac}/snmp-credential` | `credentials:write` | 403 without it |
| `PATCH /machines/{mac}` `{ipv4}` while bound | — | **409**, always |

The last row closes the same hole from the other side: repointing a bound
machine would aim the next authenticated poll at a new address without anyone
holding `credentials:write` being involved. Unbind, repoint, rebind — and the
rebind is the step that needs the scope.

The one case that is *not* blocked is OpenStack moving a managed machine's
address, which the collector follows and logs with the credential's name.
OpenStack is the address authority for those machines, and anyone who can re-IP
a server there already holds more than the credential is worth.

For the same reason the test endpoint takes no address. It polls the machine's
stored one; `{"credential": {...}}` dry-runs an unsaved credential against it.
An endpoint that probed an arbitrary address with a stored credential would be
that attack as a supported, synchronous API.

### Secrets in, never out

pysnmp needs the plaintext passphrase on every request to localize a USM key, so
these are encrypted, not hashed — `users.password_hash` is the wrong model and
copying it would produce credentials the collector cannot use.

AES-256-GCM per row, with `credential_id|key_id|secret_version` as additional
authenticated data, so ciphertext copied from one row into another fails to
decrypt rather than quietly authenticating as the wrong principal. What that
protects against is a stolen dump, replica or backup. It does *not* protect
against a compromised app container, which holds the key by construction —
protect access to `.env` and the container runtime.

No endpoint returns a secret at any scope, and this is structural: the response
model has no field one could occupy. Profiles carry a `fingerprint` — a keyed,
truncated HMAC of the secret — so a client can tell two profiles apart, or tell
whether a rotation changed anything, without reading either.

### Rotating the encryption key

`SNMP_CREDENTIAL_KEYS` is a ring, and each row records the key that sealed it:

```bash
# 1. Add the new key to SNMP_CREDENTIAL_KEYS in .env, keeping the old key.
# 2. Set SNMP_CREDENTIAL_ACTIVE_KEY to the new key id, then apply it:
make restart
# 3. Move every row to the new key:
make reencrypt
# 4. Remove the old key from SNMP_CREDENTIAL_KEYS in .env, then apply it:
make restart
```

Rows keep decrypting throughout, so step 4 can wait, and no passphrase is ever
re-entered. `make reencrypt` (`python -m app.db.reencrypt`) is safe to re-run —
rows already on the active key are skipped — and rewrapping leaves
`secret_version` alone, since the plaintext has not changed and bumping it would
re-localize every USM key in the fleet for a bookkeeping update.

Generate keys with `openssl rand -hex 32`. Losing every key in the ring means
every stored credential is unreadable and has to be entered again, so back the
ring up wherever `JWT_SECRET` is backed up. A key that goes missing while rows
still reference it is reported rather than hidden — the collector fails those
machines with `credential is encrypted under key 'k2', which is not in
SNMP_CREDENTIAL_KEYS`, and the endpoints answer 503 with the same message.

### Upgrading an installation that predates this

Nothing to do. On the first boot after the upgrade, `SNMP_COMMUNITY` is copied
into a `default-v2c` profile and every existing machine is bound to it, so a
fleet that was being polled before is still being polled after. That happens
once, guarded on the profile's creation — a later deliberate unbind is not
undone on the next restart.

`SNMP_COMMUNITY` is read at that moment and never again; the sampler has no path
to it. It can be dropped from the environment once every deployment has had that
boot.

## Configuration

`.env.example` lists every setting. Copy it to `.env` before starting Compose.
Compose uses the file for YAML interpolation and injects it into the API
container; real environment variables take precedence during interpolation.
`.env` is in `.gitignore` and `.dockerignore`, so credentials reach neither git
nor the image, but they remain visible to users who can inspect the host file or
the container runtime.

Three settings have no default and no fallback. `JWT_SECRET` is not generated
when missing, because a generated key would differ between processes — a token
minted by one rejected by the next — and would rotate on every restart,
logging everyone out. `ADMIN_USERNAME` and `ADMIN_PASSWORD` are required for the
reason in [Authentication](#authentication). A blank value counts as missing:
`ADMIN_PASSWORD=` would otherwise create an admin whose password is empty.

`SNMP_CREDENTIAL_KEYS` and `SNMP_CREDENTIAL_ACTIVE_KEY` are required too, but
only once `SNMP_SIMULATE=false` — the simulator authenticates to nothing, so a
developer running the default stack needs no key. The moment real agents are
polled the key becomes load-bearing and the app refuses to start without a
usable one: without it every credential fails to decrypt, and a monitoring
backend that reports itself healthy while collecting nothing is worse than one
that will not boot. A malformed ring is rejected either way, so a typo surfaces
locally rather than on the first real deployment.

The settings worth knowing:

| Setting | Default | Why it matters |
| --- | --- | --- |
| `COLLECTOR_INTERVAL_SECONDS` | 5 | Poll period; the loop subtracts its own runtime so the cadence does not drift |
| `COLLECTOR_CONCURRENCY` | 32 | Machines sampled in parallel. Bounds SNMP calls, not queries — see below |
| `COLLECTOR_SAMPLE_TIMEOUT_SECONDS` | 0 | Ceiling on one machine's sample; 0 derives 80% of the interval |
| `SNMP_SIMULATE` | true | false ⇒ real pysnmp against each machine's IPv4 |
| `SNMP_COMMUNITY` | public | **Read once**, to seed the `default-v2c` credential. Not a live setting — see below |
| `SNMP_CREDENTIAL_KEYS` | — | The AES-256 key ring that encrypts stored credentials. Required when `SNMP_SIMULATE=false` |
| `SNMP_CREDENTIAL_ACTIVE_KEY` | — | Which key in the ring new writes use |
| `SNMP_DISKIO_ENABLED` | true | ~6 extra walks per machine; needs the diskio view above |
| `SNMP_MAX_REPETITIONS` | 10 | Rows per GETBULK reply. Lower it for agents behind a small-MTU path — see below |
| `METRICS_COMPRESS_AFTER_HOURS` | 8 | 0 disables. TimescaleDB columnar compression |
| `METRICS_RETENTION_DAYS` | 3 | 0 disables. Raw chunks older than this are dropped |
| `METRICS_CHUNK_INTERVAL_HOURS` | 4 | New chunks only; existing ones age out |
| `METRICS_ROLLUP_1M_RETENTION_DAYS` | 90 | 0 disables. How long `metrics_1m` is kept |
| `METRICS_ROLLUP_1H_RETENTION_DAYS` | 730 | 0 disables. How long `metrics_1h` is kept |
| `METRICS_ROLLUP_REFRESH_LAG_DAYS` | 2 | How far back a rollup refresh reaches; clamped to 75% of retention |
| `METRICS_PSEUDO_MOUNT_PREFIXES` | `/run,/dev/shm,…` | Mounts excluded from `disk_max_used_pct` |
| `METRICS_VIRTUAL_IFACE_PREFIXES` | `veth,cni,…` | Interfaces excluded from the network totals |
| `OPENSTACK_SIMULATE` | true | false ⇒ read-only Nova/Keystone/Neutron lookup using a Keystone password |
| `OPENSTACK_CACHE_TTL_SECONDS` | 300 | How stale a tenant/flavor read may be |
| `OPENSTACK_API_TIMEOUT_SECONDS` | 10 | Timeout applied to each SDK HTTP request, not to the complete paginated refresh |
| `OS_AUTH_URL` | — | Keystone endpoint, `/v3` included; required for the real lookup |
| `OS_USERNAME` / `OS_USER_ID` | — | Identify the user by name or by UUID. Exactly one is required; a user id wins if both are set |
| `OS_USER_DOMAIN_ID` | default | Domain the username lives in. Ignored, and not required, when `OS_USER_ID` is used |
| `OS_PASSWORD` | — | Password for that user; required for the real lookup |
| `OS_PROJECT_ID` | — | Project UUID the session is scoped to; required for the real lookup |
| `OS_INTERFACE` | public | Service-catalog interface: public, internal or admin |
| `OS_CACERT` | — | Optional CA bundle; TLS verification cannot be disabled |
| `DB_AUTO_MIGRATE` | true | `alembic upgrade head` on startup, under an advisory lock |
| `DB_POOL_MIN` | 5 | SQLAlchemy's persistent pool, not a floor — see below |
| `JWT_SECRET` | **required** | No default. Blank or under 32 chars and the app refuses to start |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | **required** | The bootstrap account; likewise no default |
| `ADMIN_PASSWORD_RESET` | false | One-shot: rewrites the admin password from the environment |
| `ACCESS_TOKEN_TTL_SECONDS` | 900 | Access tokens cannot be revoked, so they are short |
| `REFRESH_TOKEN_TTL_SECONDS` | 1209600 | These are tracked per session and *can* be revoked |
| `LOGIN_RATE_LIMIT_MAX_PER_USER` | 5 | Failed logins per username per window before 429 |
| `LOGIN_RATE_LIMIT_MAX_PER_IP` | 20 | Same per client address; both are per process |
| `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | 300 | The window both counters slide over |
| `ROOT_PATH` | empty | Optional prefix when a reverse proxy strips a path prefix |

### Holding the cadence

A short interval is a claim about what the loop can finish, not a setting that
makes it so. Three things keep the claim honest:

**The walks run concurrently.** A machine's sample touches nineteen or so MIB
columns. Walked one after another that is nineteen round trips, and a fleet in
the hundreds cannot be polled every five seconds no matter how the concurrency is
tuned. The three tables are walked at once, and the columns within each table
too, so a sample costs about one round trip's latency rather than nineteen.

**Every sample has a deadline.** `COLLECTOR_SAMPLE_TIMEOUT_SECONDS` bounds one
machine's sample in wall-clock time, whatever the SNMP timeout and retry settings
add up to underneath. A host that never answers is recorded as a failure and
releases its concurrency slot; it cannot hold one across a whole period.

**Overruns are reported, not hidden.** The loop sleeps for whatever is left of
the period, so a tick that outruns its interval simply runs back-to-back and the
real cadence silently becomes the tick duration. When that happens it now logs a
warning and increments `overrun_count`, and `GET /admin/collector` reports
`effective_interval_seconds` — the spacing the loop is actually achieving —
beside the `interval_seconds` it was asked for. Those two diverging is the signal
to raise `COLLECTOR_CONCURRENCY` or lengthen the interval.

`POST /admin/collector/tick` returns **409** while a round is in flight. Two
rounds at once would read the same counter baselines milliseconds apart and every
rate in the second one would be noise.

### Why the metrics table is wide

`docs/metrics-storage.md` carries the full detail behind this section: the
collector and stress-test data paths, every chunk / compression / retention
policy and why it is set where it is, the continuous aggregates and the
hierarchical one that is not there, the read-path routing, and the measured
results of a 37-machine / 90-day load.

A machine writes 17,280 samples a day at a five second interval, so the size of
one sample is the whole storage question. It used to be a single jsonb blob.
Measured on a Kubernetes node, that blob averaged **4.8 KB**, and three arrays
were 73% of it:

| section | bytes | what was in it |
|---|---|---|
| `disk_io` | 1649 | 9 devices, 8 of them `loop*` carrying zeros with `counted: false` |
| `network` | 1267 | 12 interfaces, 9 of them ephemeral `veth*`/`cni0`/`flannel.1` |
| `disk` | 603 | 11 mounts, 10 of them tmpfs under `/run` |
| `ram` | 118 | |
| `cpu` | 35 | |

Nothing queried those arrays. The only field-selective query reached nine scalar
paths, and the `metrics_gin_idx` over the blob — `jsonb_path_ops`, which answers
only `@>`, `@?` and `@@` — was never used by any query in either this repo or the
frontend, while costing 0.8x the heap.

Their members are also unstable by nature: one veth per pod, renamed on every
restart. That is what rules out a column per entity, and what makes storing them
at all a poor trade against keeping them live.

Measured over 246,722 rows (7 machines, two days at 5s, values drifting
continuously rather than replayed, so nothing is flattered by repetition):

| | uncompressed | compressed | ratio |
|---|---|---|---|
| jsonb + GIN | 1930 B/row | ~284 B/row | 6.8x |
| wide row | **317 B/row** | **84 B/row** | 3.75x |
| `metrics_1m` row | 466 B/row | 146 B/row | 2.8x |

Columnar compression earns less on the wide row than on the blob — 3.75x against
6.8x — because generic LZ over repetitive text has more to remove than
delta-delta over already-narrow scalars. That is the wrong number to optimise:
the row is 6x narrower before either of them runs.

The 4-hour chunk interval costs 3.4% against day-long chunks on the same rows
(87.4 vs 84.5 B/row compressed), which is what buys most of the retention window
being compressed at all.

Confirmed at scale rather than extrapolated: 37 machines and 90 days of history,
6.75M rows resident after the raw window had aged down to three days.

| | rows | resident | per machine |
|---|---|---|---|
| raw, 3 days | 1,951,749 | 278 MB | **7.7 MB** |
| `metrics_1m`, 90 days | 4,794,103 | 745 MB | **20 MB** |
| `metrics_1h`, 90 days | 78,810 | 23 MB | 630 kB |

At the full 730-day hourly retention that is roughly **31 MB per machine** — about
4.6x less than the previous 30-day jsonb window's ~147 MB, while gaining 90 days
of minute data and two years of hourly data where there was none. Compressed cost
per row held at 83 B across the fivefold larger fleet, against 84.5 B measured on
seven machines, so this scales flat.

One operational caveat the load surfaced: inserting into an already-compressed
chunk parks the new rows in that chunk's uncompressed area, and calling
`compress_chunk` on it again does not always fold them in — one backfilled chunk
sat at 334 B/row until it was fully decompressed and recompressed, 4x its clean
size. Backfill against `metrics` should decompress the affected chunks first,
which is what revision 0004 does.

The 90-day minute rollup is the largest single consumer; halve
`METRICS_ROLLUP_1M_RETENTION_DAYS` to take roughly 11 MB per machine off the
total. At 500 machines the figures are ~16 GB against ~74 GB.

Two numbers changed meaning in the move, both because they were wrong:

* **Network totals count physical interfaces only.** They used to sum every
  interface that was up and not loopback, so a packet crossing a veth, a bridge
  and the uplink counted three times. On the Kubernetes node the reported figure
  was 46,202 B/s against 23,635 B/s actually crossing `eth0`.
* **`disk_used_percent` skips pseudo filesystems.** It used to be the maximum
  over every mount, so a full `/run/credentials/...` read as a full disk. It is
  now the fullest real filesystem, which is still not necessarily root — a full
  `/var` stays visible.

### Retention

Raw samples are kept `METRICS_RETENTION_DAYS` — three by default, which is a
troubleshooting window rather than a history. History comes from two continuous
aggregates, `metrics_1m` and `metrics_1h`, kept 90 days and two years.
`GET /metrics/stats` picks whichever source still covers the range asked for and
returns the same columns either way; the bucket is floored at what that source
can resolve.

The rollups keep `sum` and `count` per metric rather than an average, because
re-bucketing an average is only correct when every bucket held the same number of
samples — and a failed poll writes no row, while any single column can be NULL on
its own. `sum(x_sum) / sum(x_n)` stays exact at any width. They were impossible
over the jsonb shape at all: the disk figure needed `jsonb_array_elements`, and a
continuous aggregate rejects set-returning functions.

`METRICS_ROLLUP_REFRESH_LAG_DAYS` must stay shorter than the raw retention, or a
refresh is asked to re-read chunks retention has already dropped and the rollup
develops holes exactly where the raw data used to be. `policies.py` clamps it to
75% of retention and logs when it does.

Chunks are four hours rather than the seven-day default, and compression runs at
`METRICS_COMPRESS_AFTER_HOURS`. The two are tied: a chunk is only eligible once
its *end* is that far in the past, so day-long chunks with a 24 hour window would
not compress until two days old — against a three day retention, most of the
window would stay uncompressed. Four hour chunks compressed after eight hours put
roughly sixty of the seventy-two retained hours in columnar form. Both policies
and `DELETE /metrics?before=` are chunk-granular.

The policies live in `policies.py` rather than in a migration because every
window is a setting, not schema: they are removed and re-added on every startup,
so changing the setting changes the policy. A migration would pin whichever value
was configured the day it was written, and `add_*_policy(if_not_exists => TRUE)`
would then keep it and ignore the change. The aggregates themselves *are* schema,
and belong to revision `0004`.

### SQLAlchemy over psycopg2, under async endpoints

SQLAlchemy is here for the schema — Alembic diffs `db/tables.py` — and for the
identity code's ORM. It did not make the database layer async: the driver is
still psycopg2 and still synchronous, so every query runs through Starlette's
worker threadpool around a pooled connection, and the event loop never blocks.
The fleet and metric repositories kept their hand-written SQL, because
`time_bucket`, `drop_chunks` and reading a query through one of three sources
have no ORM spelling worth having. `DB_POOL_MAX` is sized for request handlers, and AnyIO's default 40 worker
threads cap how many queries can be in flight regardless of pool size. It does
**not** need to exceed `COLLECTOR_CONCURRENCY`: that semaphore bounds SNMP calls,
and a tick issues two or three queries in total — list the machines, one batched
insert — however many machines it samples. An async driver would remove the
threadpool limit; psycopg2 is the deliberate choice here, per the TigerData Python
quickstart.

Two mappings worth knowing. `DB_POOL_MIN` is SQLAlchemy's `pool_size`, which is
the *persistent* pool rather than a floor to grow from — connections past it are
opened and closed per checkout, which is why the default is now 5 and not 1. And
`executemany_mode="values_plus_batch"` on the engine is what keeps the
collector's batch insert compiling down to psycopg2's `execute_values`, one round
trip per tick.

## Authentication

Every endpoint except `/`, `/healthz` and `/readyz` needs a bearer token. The
model has three pieces:

**Scopes are fixed in code** (`src/app/security/scopes.py`) — twelve of them, two
per resource: `machines:*`, `metrics:*`, `admin:*`, `users:*`, `roles:*`,
`credentials:*`. They name capabilities the API implements, so they change only
with a deployment and have no table. `GET /scopes` returns the catalogue.

`credentials:*` is split from `machines:*` rather than folded into it because the
two authorise different amounts of damage — see
[SNMP credentials](#snmp-credentials).

**Roles are data.** An admin composes them out of scopes through `/roles`, and
`role_scopes` stores one row per grant. The built-in `admin` role holds every
scope and is flagged `is_system`: it cannot be deleted, and its scopes cannot be
edited — the boot reconciler would restore them anyway, which is what lets a
scope added to the enum reach the admin role without a migration.

**The admin account is bootstrapped from the environment.** `ADMIN_USERNAME` and
`ADMIN_PASSWORD` are required; the backend refuses to start without them, because
an API whose permissions are enforced everywhere and whose scopes nobody holds is
worse than one that will not come up. The account is created once. A password
changed through the API is *not* reverted on the next restart — set
`ADMIN_PASSWORD_RESET=true` for one boot to force-rotate a lost one.

**A password change has to change the password.** Both routes to one — the
self-service `PATCH /auth/me/password` and the administrative
`PUT /users/{id}/password` — answer 422 if the new password is the one already
in force, on top of the `PASSWORD_MIN_LENGTH` policy. Otherwise the reset would
revoke every session that account has and leave the credential untouched, which
is an outage dressed as a rotation. The self-service route compares plaintexts,
having just verified the current one; the administrative route has only the
stored hash and verifies against it, and logs the refusal — answering at all
confirms a guess to a caller who did not already know the password.

```bash
# a token
TOKEN=$(curl -fsS -X POST localhost:8000/auth/login \
  -d grant_type=password -d username=admin -d password="$ADMIN_PASSWORD" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
# or just: make token

curl -fsS -H "Authorization: Bearer $TOKEN" localhost:8000/auth/me

# a read-only role and a user holding it
curl -fsS -X POST localhost:8000/roles -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"viewer","scopes":["machines:read","metrics:read"]}'
curl -fsS -X POST localhost:8000/users -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"viewer1","password":"a-long-enough-password","roles":["viewer"]}'
```

Swagger's **Authorize** button works the same way — `/auth/login` is an OAuth2
password grant, and each operation lists the scopes it needs.

### Tokens

An **access token** (15 minutes) carries the user's scopes in its claims, so an
authenticated request costs no database queries — which is what makes it
affordable on the SSE routes. It cannot be revoked, only outlived.

A **refresh token** (14 days) carries no authority except the right to mint a new
pair, and every one is recorded in `refresh_tokens` by its `jti`. Refreshing
rotates it: the old one is revoked and linked to its successor. Presenting a
token that has already been exchanged means a copy escaped — the real client
would hold the successor — so the response is to revoke that user's entire chain,
not to fail one request.

Anything that must take effect immediately (disabling a user, changing a
password) revokes refresh tokens. Role changes are visible within one access
token's lifetime, or at once on the next refresh, which re-reads the roles.

### Failed logins

A 401 that says nothing and costs nothing is still an invitation to keep
guessing, so failures are counted (`src/app/services/ratelimit.py`) and past a
limit `/auth/login` answers **429** with `Retry-After` instead of checking the
password at all. Every attempt is counted twice:

- **Per username** — 5 failures in 5 minutes. Follows the account wherever the
  attempts come from, so spreading them across hosts buys nothing.
- **Per client address** — 20 in the same window. Catches a spray across many
  usernames, none of which is near its own limit.

Neither alone is enough: the username counter on its own would let anyone lock
any account out by failing five logins against it, which is why it is paired
with an address that also has to run out of budget. A successful login clears
the username's count and deliberately leaves the address's alone — otherwise one
valid account would reset the attacker's budget between guesses at another.

The check runs *before* the Argon2 verification, so a throttled attempt costs a
dictionary lookup rather than 19 MiB and a hash. That makes this a
denial-of-service bound as much as a credential-stuffing one.

Two things to know before relying on it. The counters are **in-process**, like
stream tickets and the metric bus, so multiple API processes multiply the
effective limit — a weaker bound, not a broken one, and the fix is a shared
store. The per-address half also depends on the app seeing the real address. If
you add a reverse proxy, configure uvicorn's `FORWARDED_ALLOW_IPS` with only the
trusted proxy addresses; otherwise every proxied caller shares one rate-limit
bucket. Application code never trusts `X-Forwarded-For` directly.

### Streaming

`EventSource` cannot set an `Authorization` header. Putting the access token in
the query string would be the obvious fix and the wrong one — a credential with
full API authority would land in proxy access logs, the browser's history and
every proxy between. So a client exchanges its token for a ticket:

```bash
TICKET=$(curl -fsS -X POST localhost:8000/auth/stream-ticket \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["ticket"])')
curl -N "localhost:8000/metrics/stream?ticket=$TICKET"
```

The ticket is single-use and lives 30 seconds, so one captured in a log is
already spent. Clients that *can* send headers — curl, anything server-side —
just use the bearer token and skip this.

### Guardrails

Permissions are the one part of a system that can be edited into an
unrecoverable state, so five things are refused outright:

- **Amplification.** You cannot grant a role holding scopes you do not hold, nor
  create one. Without this, `users:write` would silently be every permission.
- **Editing upwards.** The same subset test aimed at the target: you cannot
  edit, delete, deactivate, re-role or reset the password of an account holding
  scopes you do not, nor edit or delete a *role* holding them. Granting is not
  the only route to authority you lack — resetting the admin's password reaches
  it just as well. Since the admin role holds every scope, the practical effect
  is that **the admin account and the admin role can only be touched by another
  admin**. Peers can still administer peers, and an admin can edit anyone.
- **Editing yourself.** Not your own roles, not your own account's existence.
- **The last administrator.** Any change leaving no active user with
  `users:write` is refused — checked *after* the mutation inside the same
  transaction, since a pre-check races.
- **The system role.** `admin` cannot be deleted or have its scopes changed, and
  a role still granted to someone cannot be deleted.

Two more guard the SNMP credentials rather than the permission model — binding
takes `credentials:write`, and a bound machine's address cannot be patched. Both
exist to stop a shared credential being aimed at a host of the caller's
choosing; the reasoning is in [SNMP credentials](#snmp-credentials).

## Local development

Compose is the only runtime setup. It requires `.env`, mounts `./src` read-only,
and runs uvicorn with reload enabled.

```bash
cp .env.example .env
# Fill JWT_SECRET (openssl rand -hex 32) and ADMIN_PASSWORD in .env.

make up      # build, start, and wait until /readyz answers
make seed    # register and bind the simulated OpenStack fleet
make smoke   # check readiness, machines, and collector status
make token   # print an admin access token
open http://localhost:8000/docs
```

Without Make, use:

```bash
docker compose up -d --build --wait
docker compose exec api python /app/scripts/seed_dev.py
```

An empty `machines` table is valid but not useful. `make seed` registers the six
hosts from `app/services/openstack/simulated.py` and binds them to the
`default-v2c` credential. Keep `SNMP_CREDENTIAL_KEYS` configured in `.env`; the
bootstrap needs it to create that encrypted credential even when sampling is
simulated.

### Environment

Compose reads `.env` for interpolation and injects it into the API container.
`PGHOST=localhost` and `PGPORT=15432` are for host tools;
`compose.yaml` overrides them inside the API container with the Compose service
address and port. All other application settings flow directly from `.env` and
then fall back to defaults in `src/app/config.py`.

After changing an API setting in `.env`, run `make restart`. This recreates the
API container; `docker compose restart` alone would retain its old environment.
`PGDATABASE`, `PGUSER`, and `PGPASSWORD` initialize a new database volume and
cannot be rotated this way. Alter the database role separately, or run the
destructive `make clean` before starting with new values.

The database is published on `127.0.0.1:15432`, so host-side Alembic commands
and a host-run debugger use the same configuration:

```bash
make check
make history
PYTHONPATH=src uv run uvicorn app.main:app --port 8099
```

Dependency changes still require an image rebuild. Run `make build`, or
`make watch` to rebuild when `pyproject.toml` or `uv.lock` changes.

### SNMP test agents

The `snmp` profile starts two real net-snmp agents with authPriv users:

```bash
docker compose --profile snmp up -d snmpd snmpd2
# Set SNMP_SIMULATE=false in .env, then:
make restart
```

`snmpd2` uses the same `securityName` as `snmpd` with a different passphrase.
This exercises pysnmp's per-engine user cache behavior. Real polling also
requires a route from the API container to each agent; host-only VPN routes do
not automatically exist inside the Compose network.

### Common commands

```bash
make logs      # follow API logs
make psql      # open psql in the database container
make reencrypt # move stored credentials onto the active encryption key
make down      # stop containers and keep data
make clean     # stop containers and delete the database volume
```

## Build

The application version lives in `src/app/__init__.py`, which is also what
`GET /` reports. The Makefile derives the image tag from it:

```bash
make version   # print version and image tag
make build     # build fastapi-demo:<version>
```

Running `docker compose build` directly uses `fastapi-demo:dev` unless
`APP_VERSION` is set. The separate `version` in `pyproject.toml` is virtual
project metadata recorded by `uv.lock`; it is not the application version.

## Access

The API and Postgres are bound to loopback. `API_PORT` defaults to 8000 and
`PGPORT` defaults to 15432.

```bash
curl -s http://localhost:8000/
curl -s http://localhost:8000/readyz
open http://localhost:8000/docs
make psql
```

The API uses plain HTTP. Put a TLS-terminating reverse proxy in front before
exposing it beyond a trusted development machine. If that proxy strips a path
prefix, set `ROOT_PATH` in `.env` to the same prefix.

## Iterating

Source changes reload uvicorn automatically. Schema changes require a revision:

```bash
make revision m="add widgets"
make check
```

Read the generated revision immediately. With `DB_AUTO_MIGRATE=true`, the
reloading API applies it to the development database as soon as it starts again.

Adding a metric means a column, and touching four places: the table in
`db/tables.py`, the mapping in `services/snmp/flatten.py` (both directions), the
rollup spec in `db/rollups.py` if it belongs in long-range history, and the
revision. `tests/test_flatten.py` fails if the first two disagree.

## Teardown

`make down` removes the containers and network but keeps the named database
volume. `make clean` also removes that volume and starts the next run with an
empty database.
