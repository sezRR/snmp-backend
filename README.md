# k8s-local-image-deployment

An SNMP metrics backend: FastAPI polls cpu/ram/disk/network from a client-controlled set
of machines every 15 seconds, stores the samples in TimescaleDB, and streams them
live over SSE. It runs on a local OrbStack Kubernetes cluster with no container
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
identity and polling address and nothing else: MAC, IPv4, the client's own label,
an enabled flag. Server id, tenant, user, flavor and its specs are looked up per
request and never persisted, so there is no second copy to drift.

**MAC is identity; IPv4 is a polling address.** A client registers a machine by
IPv4 and the backend resolves the MAC from OpenStack, so an address OpenStack
does not know cannot be registered. Each collection cycle re-reads the address
from the lookup, so a re-IP'd server keeps being polled. Deleting a MAC deletes
its history.

**Metrics are one `jsonb` column.** Adding or removing a metric is a change to
the sampler alone — no migration, no model edit, and aggregates over a metric that
did not exist yet simply skip those rows.

**Both external systems are simulated, behind interfaces.** `SNMP_SIMULATE` and
`OPENSTACK_SIMULATE` pick a fake sampler and a fake fleet; real `pysnmp` is
already written and selected by the same flag, and a real `openstack.connect()`
client drops in behind the `OpenStackLookup` protocol. The simulated agent sizes
each host from its OpenStack flavor, so an `m1.small` reports 1 core and 2 GiB
rather than contradicting itself.

## Layout

| Path | Purpose |
| --- | --- |
| `src/app/main.py` | App factory and lifespan: schema, pool, lookup, sampler, collector |
| `src/app/config.py` | `pydantic-settings`; env wins over `.env` |
| `src/app/db/schema.sql` | The schema we own — `machines` + `metrics` hypertable |
| `src/app/db/init.py` | Applies it, idempotently, with retries. Also `python -m app.db.init` |
| `src/app/db/pool.py` | `ThreadedConnectionPool` + threadpool query helper |
| `src/app/db/{machines,metrics}.py` | Repositories: no ORM, plain SQL |
| `src/app/services/openstack/` | `OpenStackLookup` protocol, TTL cache, simulated fleet |
| `src/app/services/snmp/` | `SnmpSampler` protocol, pysnmp backend, simulator |
| `src/app/services/collector.py` | The 15s loop |
| `src/app/services/bus.py` | In-process pub/sub feeding SSE |
| `src/app/api/routers/` | health, machines, metrics, stream, admin |
| `.env.example` | Every setting with defaults; `.env` is git- and docker-ignored |
| `k8s/timescaledb-*.yaml` | PVC, Secret, StatefulSet, Service |
| `k8s/app-config.yaml` | Non-secret settings as a ConfigMap |
| `k8s/deployment.yaml`, `k8s/service.yaml` | The app |
| `k8s/{middleware,ingressroute,ingressroutetcp}.yaml` | Traefik routing |
| `k8s/traefik-values.yaml` | Helm values: `web` + `postgres` entryPoints, CRD provider only |

## Data model

`src/app/db/schema.sql`, applied by the app on startup:

```sql
CREATE TABLE machines (
    mac        macaddr PRIMARY KEY,      -- identity, resolved from OpenStack
    ipv4       inet    NOT NULL UNIQUE,  -- what the collector polls
    label      text,                     -- the client's own annotation
    enabled    boolean NOT NULL DEFAULT true,
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
against an empty data directory, so it cannot be evolved. This file is re-applied
on every startup and stays idempotent. `DB_AUTO_INIT=false` hands the schema to
something else.

The FK is what makes "delete the MAC, delete its history" one statement. A
hypertable may reference a regular table; the cascade touches every chunk, which
is fine at this scale — time-ranged purges use `drop_chunks` instead.

A sample looks like:

```json
{"cpu":  {"usage_percent": 22.93, "cores": 1},
 "ram":  {"total_bytes": 2147483648, "used_bytes": 727130208, "used_percent": 33.86},
 "disk": [{"mount": "/", "total_bytes": 21474836480, "used_bytes": 8967258924, "used_percent": 41.76}],
 "network": {"rx_bps": 812344.5, "tx_bps": 1904771.2,
             "rx_bytes": 402653184000, "tx_bytes": 915678412000,
             "interval_seconds": 15.02,
             "interfaces": [{"name": "eth0", "rx_bps": 812344.5, "tx_bps": 1904771.2,
                             "rx_bytes": 402653184000, "tx_bytes": 915678412000,
                             "speed_bps": 1000000000,
                             "rx_util_percent": 0.65, "tx_util_percent": 1.52}]}}
```

Bandwidth is a rate SNMP does not report: agents expose cumulative octet
counters, so `rx_bps`/`tx_bps` are **bytes per second** derived from the delta
against the previous sample of that host. They are null on the first sample
after a restart, and on a counter that reset in between — the raw
`rx_bytes`/`tx_bytes` counters are stored alongside so any window can be
recomputed from history. Loopback and down interfaces are excluded.

## API

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/` | service info and which backends are simulated |
| GET | `/healthz` | no dependencies — backs liveness |
| GET | `/readyz` | queries Postgres — backs readiness |
| POST | `/machines` | `{ipv4, label?}`; 404 if OpenStack does not know the address, 409 if already registered |
| GET | `/machines` | our rows enriched with server id, tenant, user, flavor + specs |
| GET/PATCH/DELETE | `/machines/{mac}` | `PATCH {label?, enabled?}`; `DELETE` cascades the history |
| GET | `/metrics` | `?mac=&since=&limit=` — repeat `mac` to filter on several |
| GET | `/metrics/latest` | most recent sample per machine |
| GET | `/metrics/stats` | `?bucket=1 minute&hours=1&mac=` — `time_bucket` over the jsonb |
| GET | `/metrics/counts` | rows and latest sample per machine |
| GET | `/metrics/stream` | SSE firehose, `?mac=` to filter |
| GET | `/machines/{mac}/metrics/stream` | SSE for one machine |
| DELETE | `/machines/{mac}/metrics` | purge one machine's history, `?before=` for a range |
| DELETE | `/metrics` | purge everything; **requires `?confirm=true`**. `?before=` drops whole chunks instead |
| GET | `/admin/collector` | loop health and per-machine ok/fail counts |
| POST | `/admin/collector/tick` | run one round now instead of waiting |
| GET | `/admin/openstack/cache` | ttl, age, hits, misses, refreshes |
| GET | `/admin/openstack/servers` | the fleet as cached — the registerable addresses |
| POST | `/admin/openstack/cache/flush` | drop the cache; next read repopulates |

Streaming is a side channel: samples are written to TimescaleDB first and
published second, so subscribing changes nothing about what is stored, and events
arrive at the collector's cadence rather than on demand. The bus is per-pod — with
more than one replica a client only sees what its pod collected.

## Configuration

`.env.example` lists every setting. Real environment variables always win over the
file, so in Kubernetes the values come from `k8s/app-config.yaml` (non-secret) and
`k8s/timescaledb-secret.yaml` (credentials), both mounted with `envFrom`. `.env`
is in `.gitignore` and `.dockerignore`, so credentials reach neither git nor the
image.

The settings worth knowing:

| Setting | Default | Why it matters |
| --- | --- | --- |
| `COLLECTOR_INTERVAL_SECONDS` | 15 | Poll period; the loop subtracts its own runtime so the cadence does not drift |
| `COLLECTOR_CONCURRENCY` | 10 | Machines sampled in parallel; keep `DB_POOL_MAX` above it |
| `SNMP_SIMULATE` | true | false ⇒ real pysnmp against each machine's IPv4 |
| `OPENSTACK_SIMULATE` | true | false ⇒ needs `openstacksdk` and a real adapter |
| `OPENSTACK_CACHE_TTL_SECONDS` | 300 | How stale a tenant/flavor read may be |
| `DB_AUTO_INIT` | true | Apply `schema.sql` on startup |
| `ROOT_PATH` | `/api` in-cluster | Must match the IngressRoute path and its StripPrefix |

### psycopg2 under async endpoints

Endpoints are `async def` and psycopg2 is synchronous, so every query runs through
Starlette's worker threadpool around a pooled connection — the event loop never
blocks. Two consequences: `DB_POOL_MAX` must exceed `COLLECTOR_CONCURRENCY` plus
request headroom, and AnyIO's default 40 worker threads cap how many queries can
be in flight regardless of pool size. An async driver would remove both limits;
psycopg2 is the deliberate choice here, per the TigerData Python quickstart.

## Build

```bash
docker build -t fastapi-demo:0.4.0 .
```

Locally, against a throwaway database:

```bash
docker run -d --name tsdb -e POSTGRES_DB=app -e POSTGRES_USER=app \
  -e POSTGRES_PASSWORD=smoke -p 15499:5432 timescale/timescaledb:2.22.1-pg17
cp .env.example .env      # then set PGPORT=15499, PGPASSWORD=smoke
PYTHONPATH=src uv run uvicorn app.main:app --port 8099
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

> **Unauthenticated plain HTTP, with `/api/docs` browsable and `DELETE /metrics`
> reachable.** Anything on the network can read, write and purge. Fine on a
> trusted home LAN; do not run it on shared or public Wi-Fi. If the macOS firewall
> is enabled it will block this and you will need an inbound allow rule for
> OrbStack.

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

```bash
docker build -t fastapi-demo:0.4.1 .
kubectl set image deploy/fastapi fastapi=fastapi-demo:0.4.1
kubectl rollout status deploy/fastapi
```

If you do reuse a tag while experimenting, force the swap:

```bash
kubectl rollout restart deploy/fastapi
```

Changing the schema means editing `src/app/db/schema.sql` — keep it idempotent,
since it re-runs on every startup. Adding a metric means editing only the sampler:
the `jsonb` column takes any shape, and `metrics/stats` skips samples that lack a
key.

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
