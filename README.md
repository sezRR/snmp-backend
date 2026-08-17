# k8s-local-image-deployment

An SNMP metrics backend: FastAPI polls cpu, ram, disk capacity, disk throughput
and IOPS, and network from a client-controlled set of machines every 5 seconds,
stores the samples in TimescaleDB, and streams them live over SSE. It runs on a local OrbStack Kubernetes cluster with no container
registry involved at any point, behind Traefik — HTTP under `/api`, raw Postgres
over an `IngressRouteTCP`.

## Why no registry is needed

OrbStack's Kubernetes runs on the *same* Docker daemon as your `docker` CLI:

```
$ kubectl get nodes -o wide
NAME       STATUS   VERSION          CONTAINER-RUNTIME
orbstack   Ready    v1.34.8+orb1     docker://29.4.0
```

So an image built with `docker build` is already in the cluster's image store.
There is no `docker push`, no `kind load docker-image`, no `minikube image load`.
The Deployment just sets `imagePullPolicy: IfNotPresent` so the kubelet uses the
local image instead of trying to reach Docker Hub.

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

**Metrics are one `jsonb` column.** Adding or removing a metric is a change to
the sampler alone — no migration, no model edit, and aggregates over a metric that
did not exist yet simply skip those rows.

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
| `src/app/db/policies.py` | Compression and retention: settings, not schema, so re-applied every boot |
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
| `src/app/services/collector.py` | The 15s loop |
| `src/app/services/bus.py` | In-process pub/sub feeding SSE |
| `src/app/api/routers/` | health, auth, users, roles, machines, credentials, metrics, stream, admin |
| `alembic.ini` | Host CLI only; the app builds an equivalent config in code |
| `.env.example` | Every setting with defaults; `.env` is git- and docker-ignored |
| `compose.yaml` | Both processes on one host: the deployable shape |
| `compose.override.yaml` | Development overlay — bind mount, `--reload`, published database |
| `scripts/seed_dev.py` | Registers the simulated fleet against a running API, then binds credentials |
| `Makefile` | `up`, `seed`, `psql`, `logs`, `reencrypt`, `clean` for the Compose stack |
| `k8s/timescaledb-*.yaml` | PVC, Secret, StatefulSet, Service |
| `k8s/app-config.yaml` | Non-secret settings as a ConfigMap |
| `k8s/api-secrets.yaml` | API, SNMP encryption and OpenStack secrets, kept out of the database Secret |
| `k8s/deployment.yaml`, `k8s/service.yaml` | The app |
| `k8s/{middleware,ingressroute,ingressroutetcp}.yaml` | Traefik routing |
| `k8s/traefik-values.yaml` | Helm values: `web` + `postgres` entryPoints, CRD provider only |

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
    ts      timestamptz NOT NULL,
    mac     macaddr     NOT NULL REFERENCES machines (mac) ON DELETE CASCADE,
    metrics jsonb       NOT NULL
);
SELECT create_hypertable('metrics', by_range('ts'));
```

Deliberately *not* loaded through `/docker-entrypoint-initdb.d`: that only runs
against an empty data directory, so it could never be evolved. Migrations run on
every startup instead, under a Postgres advisory lock so replicas starting
together do not race. `DB_AUTO_MIGRATE=false` hands the schema to something else
— a Job running `python -m app.db.migrate`, say.

Revision `0001` no-ops on a database that already has `machines`, so a cluster
deployed before Alembic is adopted by the same `upgrade head` that builds a fresh
one, with no manual `alembic stamp`.

The identity tables are `users`, `roles`, `role_scopes`, `user_roles` and
`refresh_tokens` — see [Authentication](#authentication). `snmp_credentials` has
its own section: [SNMP credentials](#snmp-credentials).

Revision `0003` creates the credential table but does not populate it. Seeding
needs the encryption key ring, and Alembic deliberately loads only
`DatabaseSettings` — so a migration Job never has to be handed one. The
`default-v2c` row is written by `app.services.bootstrap` on the first boot that
finds none.

The FK is what makes "delete the MAC, delete its history" one statement. A
hypertable may reference a regular table; the cascade touches every chunk, which
is fine at this scale — time-ranged purges use `drop_chunks` instead.

A sample looks like:

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

`compose.override.yaml` has an `snmpd` service under the `snmp` profile that is
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
times out. Polling over Tailscale (1280-byte MTU) from a pod, 25 rows of
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
| GET | `/metrics/stats` | `metrics:read` | `?bucket=1 minute&hours=1&mac=` — `time_bucket` over the jsonb |
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
arrive at the collector's cadence rather than on demand. The bus is per-pod — with
more than one replica a client only sees what its pod collected.

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
against a compromised pod, which holds the key by construction — keep the
Secret's RBAC as the thing guarding that.

No endpoint returns a secret at any scope, and this is structural: the response
model has no field one could occupy. Profiles carry a `fingerprint` — a keyed,
truncated HMAC of the secret — so a client can tell two profiles apart, or tell
whether a rotation changed anything, without reading either.

### Rotating the encryption key

`SNMP_CREDENTIAL_KEYS` is a ring, and each row records the key that sealed it:

```bash
SNMP_CREDENTIAL_KEYS='{"k1":"<hex>","k2":"<new hex>"}'   # 1. add, keep the old
SNMP_CREDENTIAL_ACTIVE_KEY=k2                            # 2. flip, restart
make reencrypt                                           # 3. move every row
SNMP_CREDENTIAL_KEYS='{"k2":"<new hex>"}'                # 4. drop the old
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

### Upgrading a deployment that predates this

Nothing to do. On the first boot after the upgrade, `SNMP_COMMUNITY` is copied
into a `default-v2c` profile and every existing machine is bound to it, so a
fleet that was being polled before is still being polled after. That happens
once, guarded on the profile's creation — a later deliberate unbind is not
undone on the next restart.

`SNMP_COMMUNITY` is read at that moment and never again; the sampler has no path
to it. It can be dropped from the environment once every deployment has had that
boot.

## Configuration

`.env.example` lists every setting. Real environment variables always win over the
file, so in Kubernetes the values come from `k8s/app-config.yaml` (non-secret),
`k8s/timescaledb-secret.yaml` (database credentials) and `k8s/api-secrets.yaml`
(the signing key, the bootstrap password and the SNMP credential key ring), all
three mounted with `envFrom`.
`.env` is in `.gitignore` and `.dockerignore`, so credentials reach neither git
nor the image.

Three settings have no default and no fallback. `JWT_SECRET` is not generated
when missing, because a generated key would differ between replicas — a token
minted by one pod rejected by the next — and would rotate on every restart,
logging everyone out. `ADMIN_USERNAME` and `ADMIN_PASSWORD` are required for the
reason in [Authentication](#authentication). A blank value counts as missing:
`ADMIN_PASSWORD=` is exactly what an unfilled ConfigMap key produces, and it
would otherwise create an admin whose password is the empty string.

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
| `METRICS_COMPRESS_AFTER_HOURS` | 24 | 0 disables. TimescaleDB columnar compression |
| `METRICS_RETENTION_DAYS` | 30 | 0 disables. Chunks older than this are dropped |
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
| `LOGIN_RATE_LIMIT_MAX_PER_IP` | 20 | Same per client address; both are per replica |
| `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | 300 | The window both counters slide over |
| `ROOT_PATH` | `/api` in-cluster | Must match the IngressRoute path and its StripPrefix |

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

### Retention

At a five second interval a machine writes 17,280 samples a day, so a fleet in
the hundreds writes millions of rows and gigabytes of jsonb a day. `app.db.policies`
therefore schedules two TimescaleDB jobs on the hypertable — compression after
`METRICS_COMPRESS_AFTER_HOURS`, dropping chunks after `METRICS_RETENTION_DAYS` —
and chunks are one day rather than the seven-day default, since both policies and
`DELETE /metrics?before=` are chunk-granular.

The policies live in `policies.py` rather than in a migration because both
windows are settings, not schema: they are removed and re-added on every startup,
so changing the setting changes the policy. A migration would pin whichever value
was configured the day it was written, and `add_*_policy(if_not_exists => TRUE)`
would then keep it and ignore the change.

### SQLAlchemy over psycopg2, under async endpoints

SQLAlchemy is here for the schema — Alembic diffs `db/tables.py` — and for the
identity code's ORM. It did not make the database layer async: the driver is
still psycopg2 and still synchronous, so every query runs through Starlette's
worker threadpool around a pooled connection, and the event loop never blocks.
The fleet and metric repositories kept their hand-written SQL, because
`time_bucket`, `drop_chunks` and the jsonb lateral aggregate have no ORM spelling
worth having. `DB_POOL_MAX` is sized for request handlers, and AnyIO's default 40 worker
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
stream tickets and the metric bus, so at `replicas > 1` the effective limit is
these numbers times the replica count — a weaker bound, not a broken one, and
the fix is a shared store this deployment does not have. And the per-address
half depends on the app seeing the real address: requests arrive from Traefik,
so `FORWARDED_ALLOW_IPS` on the Deployment is what lets uvicorn believe
`X-Forwarded-For`. Without it every caller shares Traefik's pod address and the
20-per-address limit becomes one bucket for the whole cluster. The header is
never read in application code, only by uvicorn's middleware, which trusts it
solely from the addresses listed there.

### Streaming

`EventSource` cannot set an `Authorization` header. Putting the access token in
the query string would be the obvious fix and the wrong one — a credential with
full API authority would land in Traefik's access log, the browser's history and
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

Kubernetes is how this is deployed, not how it is developed: a code change there
costs a build, a tag bump and a rollout. Compose runs the same two processes with
the source mounted, so a save reloads the server.

```bash
make up      # build, start, wait until /readyz answers
make seed    # register the simulated OpenStack fleet
make smoke   # readyz, then machines and collector status with a token
make token   # print an admin access token, for pasting into curl
open http://localhost:8000/docs
```

`compose.override.yaml` supplies committed dev values for `JWT_SECRET` and
`ADMIN_PASSWORD`, so this works on a clean checkout with no `.env` at all. The
admin account is `admin` / `dev-only-admin-password`. Override either in `.env`;
`compose.yaml` on its own invents neither, so the deployed shape fails loudly
instead of running on a signing key that is in this repository.

Without `make`, that is `docker compose up -d --build --wait` and
`docker compose --profile seed run --rm seed`. Requires Compose v2.24 or newer.

`compose.yaml` holds the stack; `compose.override.yaml`, which Compose loads
automatically, is what makes it a development environment:

| | `docker compose up` | `docker compose -f compose.yaml up` |
| --- | --- | --- |
| Source | `./src` mounted read-only over the image's copy, `uvicorn --reload` | Baked into the image |
| Database port | published on `127.0.0.1:15432` | not published |
| SNMP / OpenStack | simulated | whatever `.env` says |
| Restart policy | none | `unless-stopped` |
| `JWT_SECRET` / `ADMIN_PASSWORD` | committed dev defaults | must be supplied |
| Root filesystem | writable | read-only, `cap_drop: ALL` |

Both build the tag in `APP_VERSION`, which the Makefile derives from
`src/app/__init__.py` — see [Build](#build). Invoked without `make`, and with no
`APP_VERSION` set, they build `fastapi-demo:dev` instead, so a bare
`docker compose build` can never land on the tag the cluster is pinned to.

An empty `machines` table is why a fresh stack looks broken — the collector ticks
against nothing and every endpoint returns `[]`. `make seed` registers the six
hosts `app/services/openstack/simulated.py` serves, by address only, so their
MACs and flavors come from the lookup exactly as a real machine's would. It then
binds each one to the `default-v2c` credential, because registering alone leaves
a machine unpolled — two calls, since binding needs its own scope. Re-running is
a no-op on both halves.

The overlay sets a committed `SNMP_CREDENTIAL_KEYS` even though the simulated
stack does not strictly need one: without it there is nothing to seed
`default-v2c` with, so nothing could be bound and the stack would come up
healthy and collect nothing.

To exercise real SNMPv3 rather than the simulator, the `snmp` profile starts
net-snmp agents with an authPriv user:

```bash
docker compose --profile snmp up -d snmpd snmpd2
# then set SNMP_SIMULATE=false in .env, restart, register them by address and
# bind an authPriv credential — see SNMP credentials.
```

`snmpd2` carries the *same* `securityName` as `snmpd` with a different
passphrase. That is not redundancy: pysnmp caches USM users on an engine under
`(userName, securityEngineId)`, so two such credentials on one shared engine
tear each other's registration down mid-tick. The sampler gives each credential
its own `SnmpEngine`, and these two agents are the smallest setup that can prove
it.

The rest:

```bash
make logs      # follow the app
make psql      # psql inside the database container
make reencrypt # move stored credentials onto the active encryption key
make down      # stop, keep the data
make clean     # stop and delete the volume
```

The database is on `127.0.0.1:15432` for host tools — 15432 rather than 5432 so
it never collides with the cluster's `IngressRouteTCP`, which already owns the
Mac's 5432, and loopback-only because OrbStack publishes on every interface and
that password is committed in plaintext. Running uvicorn on the host against it
still works, and is the faster loop for debugger work:

```bash
cp .env.example .env      # PGPORT is already 15432; fill in the blank values
printf 'JWT_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env
printf 'ADMIN_PASSWORD=dev-only-admin-password\n' >> .env
PYTHONPATH=src uv run uvicorn app.main:app --port 8099
```

The same `.env` is what the Alembic targets read — `make revision`, `make check`
and `make history` run on the host against the published database port.

Dependency changes are the one thing a save cannot pick up, since they live in
the image: `make build`, or `make watch` to have Compose rebuild whenever
`pyproject.toml` or `uv.lock` changes.

### Where the settings come from

Compose reads `.env` twice — once to expand `${...}` in the YAML, once as the
api container's env file — and the file is optional, so a clean checkout starts
without one. The three variables that describe container topology rather than
preference (`PGHOST`, `PGPORT`, `ROOT_PATH`) are pinned under `environment:` in
`compose.yaml`, because a `.env` written for host-run uvicorn says
`PGHOST=localhost` and `PGPORT=15432`, which would send the container to itself.
Everything else falls through to `.env` and then to the defaults in
`src/app/config.py`.

Real SNMP polling from Compose needs one more thing than `SNMP_SIMULATE=false`:
a route from the container to the agents. A Tailscale address that resolves on
the Mac does not automatically resolve inside a bridge-network container, which
is the same reason the cluster's polling is verified from inside the pod rather
than from the host.

### Can this deploy the app too?

It can, on a single host, and `compose.yaml` alone is written to be that shape —
that is why the dev conveniences are quarantined in the override rather than
sprinkled through the base file. On a machine that is not a laptop:

```bash
docker compose -f compose.yaml up -d --build --wait
```

What you keep: identical images, pinned database version, health-gated startup
ordering, restart-on-failure, a named volume, a read-only root filesystem and
dropped capabilities. Which is close to feature parity with what `k8s/` actually
provides here, because that cluster is a single node with a single replica and a
standalone PVC — there is no HA to lose.

What you give up, and what to weigh it against:

* **No rolling update.** `compose up` stops the old container before starting the
  new one, so a deploy is a few seconds of downtime; `kubectl rollout` gates the
  new pod on its probes and never drops the old one until it passes. With
  `replicas: 1` and a collector that resumes on the next tick, that gap is
  cheap — but it is a real difference, and a `--wait` failure leaves you rolling
  back by hand.
* **No ingress, no TLS.** The app is published straight on a host port. The
  Traefik `IngressRoute`, its `StripPrefix` middleware and the `ROOT_PATH=/api`
  that pairs with it have no equivalent here; a Compose deployment behind a
  reverse proxy has to reproduce both.
* **Secrets are environment variables.** `PGPASSWORD` comes from `.env` on disk
  next to the compose file, visible in `docker inspect`. A Secret is not much
  better, but it is at least a separate object with its own access path.
* **Two places to change a setting.** `k8s/app-config.yaml` and `.env` describe
  the same `Settings`, and nothing keeps them in step. This is the maintenance
  cost of having both, and the reason not to grow a third.

The recommendation is to treat `k8s/` as the deployment target of record and
Compose as the development environment, with single-host Compose deployment as a
deliberate fallback rather than a parallel path — because keeping two full
deployment stories honest costs more than either is worth here. Do not try to
generate one from the other (`kompose` and friends): the manifests encode
things Compose cannot express, such as the `startupProbe` that keeps a slow
database from restart-looping the app, and the deliberate `secretKeyRef` that
keeps `PGHOST` out of the database container.

## Build

The version lives in exactly one place — `src/app/__init__.py`, which is also
what the running app reports from `GET /` — and the image tag is derived from it:

```bash
make version   # 0.7.0  ->  fastapi-demo:0.7.0
make build     # docker compose build, tagged fastapi-demo:0.7.0
```

The Makefile reads that string with `sed` and exports it as `APP_VERSION`, which
`compose.yaml` expands into the `image:` tag. So an image built for the
development stack is also the one `kubectl set image` points the Deployment at,
and `make deploy-tag` prints that command with the derived tag filled in.

Bare `docker compose build`, with no `APP_VERSION` in the environment, falls back
to `fastapi-demo:dev`. That is deliberate: `imagePullPolicy: IfNotPresent` means
whatever sits on the cluster's tag is what the next rollout runs, so a laptop
build must not be able to land there by accident. Build the cluster's tag on
purpose, with `make build` or `APP_VERSION=0.7.0 docker compose build`.

The `version` in `pyproject.toml` is a different number and is meant to stay
that way — it is the virtual project's own metadata, `uv.lock` records it, and
raising it to match only makes `uv sync --locked` fail the image build until
`uv lock` is re-run. Nothing installs this package, so that relock buys nothing.

Or without any of that:

```bash
docker build -t fastapi-demo:0.7.0 .
```

## Deploy

Traefik goes in first — `ingressroute.yaml`, `middleware.yaml` and
`ingressroutetcp.yaml` are `traefik.io/v1alpha1` objects, so `kubectl apply -k`
fails until the chart has installed the CRDs.

```bash
kubectl config use-context orbstack

helm repo add traefik https://traefik.github.io/charts
helm repo update traefik
helm upgrade --install traefik traefik/traefik \
  --namespace traefik --create-namespace \
  -f k8s/traefik-values.yaml --wait
```

Then the database and the app:

```bash
kubectl apply -k k8s/
kubectl rollout status statefulset/timescaledb --timeout=180s
kubectl rollout status deploy/fastapi --timeout=180s
```

The app applies its schema during startup and retries while Postgres is still
running `initdb`, which is why the Deployment has a `startupProbe` — liveness and
readiness stay suppressed until the first `/healthz` succeeds, so a slow database
cannot cause a restart loop.

Confirm nothing was pulled from a registry — the event should read
`already present on machine`, never `Pulling`:

```bash
kubectl describe pod -l app=fastapi | grep -i pull
```

### The TimescaleDB manifests

They follow [TigerData's Kubernetes install][k8s-doc] for a single node: a
standalone `PersistentVolumeClaim` (not `volumeClaimTemplates`), a Secret of
`PG*`/`POSTGRES_*` literals, a ClusterIP Service, `replicas: 1`, no HA and no
operator. Two deliberate departures:

* the image stays `timescale/timescaledb:2.22.1-pg17` rather than the doc's
  `timescale/timescaledb-ha:pg18`;
* everything stays in the `default` namespace instead of `tigerdata`, so the
  `IngressRouteTCP` service reference and the Secret stay local.

The database container gets its three `POSTGRES_*` keys by explicit
`secretKeyRef`, **not** `envFrom` the whole Secret. The Secret also carries the
app's `PGHOST`, and this image's own init scripts call `psql` — given `PGHOST`
they dial the Service over TCP while only the temporary unix-socket server is up,
fail with `connection refused`, and the container restarts.

[k8s-doc]: https://www.tigerdata.com/docs/get-started/choose-your-path/install-timescaledb#tab=kubernetes

## Access

### HTTP, from this Mac

```bash
curl -s http://localhost/api/                       # service info
curl -s http://localhost/api/readyz                 # {"status":"ok","timescaledb":"2.22.1"}
open http://localhost/api/docs                      # Swagger UI

# which addresses can be registered
curl -s http://localhost/api/admin/openstack/servers

curl -s -X POST http://localhost/api/machines \
  -H 'content-type: application/json' \
  -d '{"ipv4":"10.0.0.11","label":"web-1"}'

# a machine outside OpenStack: no record to resolve, so give the MAC
curl -s -X POST http://localhost/api/machines \
  -H 'content-type: application/json' \
  -d '{"ipv4":"192.168.1.50","mac":"de:ad:be:ef:00:01","label":"nas"}'

# registering does not start polling — bind a credential, which needs
# credentials:write rather than machines:write
curl -s http://localhost/api/snmp-credentials
curl -s -X PUT http://localhost/api/machines/de:ad:be:ef:00:01/snmp-credential \
  -H 'content-type: application/json' \
  -d '{"credential_id":"<id>"}'

curl -s http://localhost/api/machines               # rows + OpenStack details
curl -s 'http://localhost/api/metrics?limit=5'
curl -s 'http://localhost/api/metrics/stats?bucket=1%20minute&hours=1'
curl -sN http://localhost/api/metrics/stream        # live, one batch per 15s
```

Anything outside `/api` has no route and Traefik answers `404 page not found`.

```bash
kubectl get ingressroute,ingressroutetcp,middleware    # the routing objects
```

### Postgres, from this Mac

Through the `IngressRouteTCP` on port 5432 — any Postgres client works:

```bash
PGPASSWORD=dev-only-not-a-secret psql -h localhost -p 5432 -U app -d app \
  -c 'SELECT mac, count(*), max(ts) FROM metrics GROUP BY 1;'
```

No local `psql`? Reuse the image, and reach the host from inside the container:

```bash
docker run --rm -e PGPASSWORD=dev-only-not-a-secret \
  timescale/timescaledb:2.22.1-pg17 \
  psql -h host.docker.internal -p 5432 -U app -d app -c 'SELECT count(*) FROM metrics;'
```

Or skip the network entirely:

```bash
kubectl exec -it timescaledb-0 -- psql -U app -d app
kubectl exec timescaledb-0 -- psql -U app -d app \
  -c 'SELECT * FROM timescaledb_information.hypertables;'
```

> ⚠️ **Port 5432 is published on every interface, with no TLS.** The committed
> password is the only access control, and it is in git. Anyone on the network can
> connect as `app`, which owns the database. Override the Secret (instructions
> inside `k8s/timescaledb-secret.yaml`) before running this anywhere but a trusted
> machine, or drop the `postgres` entryPoint from `k8s/traefik-values.yaml` and use
> `kubectl port-forward` instead.

### Routing

```
localhost/api/metrics -> Traefik (web) -> StripPrefix(/api) -> svc/fastapi:80 -> pod:8000 /metrics
localhost:5432        -> Traefik (postgres)                 -> svc/timescaledb:5432 -> timescaledb-0
```

Routing is expressed as Traefik CRDs (`IngressRoute`, `IngressRouteTCP`,
`Middleware`) rather than a `networking.k8s.io/v1` Ingress. A plain Ingress cannot
strip a prefix on its own, so the `Middleware` CRD is required either way — and
referencing it from an Ingress means a stringly-typed annotation
(`traefik.ingress.kubernetes.io/router.middlewares: default-fastapi-stripprefix@kubernetescrd`)
where a typo is silently ignored and the app sees an unstripped `/api/...` path.
The trade is portability: another controller means rewriting these objects, and
`Ingress`-shaped tooling (cert-manager's ingress-shim, external-dns) cannot see
them.

The TCP route matches `HostSNI(`*`)`, the only matcher a non-TLS TCP route
accepts. Postgres cannot be SNI-routed anyway — its TLS upgrade is negotiated
inside the wire protocol — so that entryPoint serves exactly one backend; a second
database would need another port.

The app does **not** use the TCP route: it talks to `svc/timescaledb:5432` over
cluster DNS.

### From other devices on the LAN

Because `orb config` has `docker.expose_ports_to_lan: true`, OrbStack binds those
ports on *all* interfaces, not just loopback:

```bash
ipconfig getifaddr en0        # this Mac's LAN address
```

```
http://<MAC_LAN_IP>/api/          -> service info
http://<MAC_LAN_IP>/api/docs      -> Swagger UI
<MAC_LAN_IP>:5432                 -> Postgres
```

> **Plain HTTP.** Endpoints need a bearer token, but nothing is encrypted in
> transit — a password posted to `/api/auth/login` and every token after it cross
> the network in the clear, and `k8s/api-secrets.yaml` ships a committed demo
> signing key that anyone reading this repository can forge tokens with. Replace
> both Secrets and put TLS in front of Traefik before running anywhere that is
> not a trusted machine. If the macOS firewall is enabled it will block this and
> you will need an inbound allow rule for OrbStack.

### Port-forward

Independent of host networking — it tunnels through the Kubernetes API server, so
it works even when OrbStack's routing does not.

```bash
kubectl port-forward svc/fastapi 8080:80          # straight to the app, no /api prefix
curl -s localhost:8080/healthz

kubectl port-forward -n traefik svc/traefik 8080:80   # through Traefik, prefix intact
curl -s localhost:8080/api/healthz

kubectl port-forward svc/timescaledb 15432:5432       # database, without publishing 5432
```

### Known OrbStack quirk

Container and Service IPs themselves (`192.168.194.x`, `192.168.139.2`) and
`*.orb.local` / `*.svc.cluster.local` names may fail from macOS with
`No route to host`, even while the published ports above work perfectly. That is
OrbStack's host↔VM routing being down, not a problem with these manifests —
plain `docker` container IPs will be unreachable too. Restarting OrbStack
restores it.

## Iterating

Tags are deliberately versioned rather than `latest`. With `latest` plus
`imagePullPolicy: IfNotPresent`, a rebuild leaves the old image running and the
rollout silently does nothing.

Bumping one is a single edit — `__version__` in `src/app/__init__.py` — after
which the build tag, the rollout command and what `GET /` reports all follow:

```bash
make build         # fastapi-demo:<new version>
make deploy-tag    # prints the two kubectl lines with that tag
```

```bash
kubectl set image deploy/fastapi fastapi=fastapi-demo:0.7.1
kubectl rollout status deploy/fastapi
```

`deploy-tag` prints rather than runs: a Make target should not mutate a cluster.
`k8s/deployment.yaml` still carries the tag it was last deployed with, so update
it there too when the bump is meant to be permanent.

If you do reuse a tag while experimenting, force the swap:

```bash
kubectl rollout restart deploy/fastapi
```

Changing the schema means editing `src/app/db/tables.py` and generating a
revision from it:

```bash
make revision m="add widgets"   # autogenerated from the diff, on the host
make check                      # passes when tables.py and the migrations agree
```

Read the generated file before it runs. The dev container bind-mounts `./src`,
reloads on change and boots with `DB_AUTO_MIGRATE=true`, so a revision is applied
to the dev database the moment it lands — `make clean` if you then change your
mind. Revisions are authored on the host, not in the container: `read_only: true`
here and `readOnlyRootFilesystem: true` in Kubernetes both forbid writing them.

Adding a *metric* still needs no migration at all: the `jsonb` column takes any
shape, and `metrics/stats` skips samples that lack a key.

## Teardown

`kubectl delete -k` removes the StatefulSet but **not** the PVC — that is
Kubernetes' deliberate default, so the data survives. Delete it explicitly to
start from an empty database:

```bash
kubectl delete -k k8s/
kubectl delete pvc timescaledb-pvc
helm uninstall traefik -n traefik && kubectl delete ns traefik
```

`helm uninstall` leaves the Traefik CRDs behind by design (they are unlabelled, so
there is no selector for them); if you want the cluster back to how it started:

```bash
kubectl get crd -o name | grep traefik.io | xargs kubectl delete
```
