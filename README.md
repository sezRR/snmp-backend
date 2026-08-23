# SNMP Metrics API

Collect CPU, memory, disk, and network metrics from SNMP-enabled machines. The
API stores metric history in TimescaleDB and provides current readings, trends,
and live updates.

## Prerequisites

- Docker with Docker Compose
- `make` for the command shortcuts below
- Network access to UDP port 161 on each machine you want to monitor

## Quick start

1. Create your local configuration:

   ```bash
   cp .env.example .env
   ```

2. Open `.env` and set these required values:

   ```dotenv
   PGPASSWORD=<database-password>
   JWT_SECRET=<at-least-32-characters>
   ADMIN_PASSWORD=<at-least-12-characters>
   ```

   Generate strong values with `openssl rand -hex 32`. The included
   `SNMP_CREDENTIAL_KEYS` value is for local use only; replace it before using
   the service in another environment.

3. Choose how machines will be discovered:

   - Without OpenStack, set `OPENSTACK_ENABLED=false`.
   - With OpenStack, keep it enabled and fill in the `OS_*` settings in `.env`.

4. Start the API and database:

   ```bash
   make up
   ```

5. Open the interactive API at <http://localhost:8000/docs>. Select
   **Authorize** and sign in with `ADMIN_USERNAME` and `ADMIN_PASSWORD` from
   `.env`.

Check that the service is ready:

```bash
curl -fsS http://localhost:8000/readyz
```

## Add a machine

Before adding a machine, make sure its SNMP agent is reachable from the API.

In the interactive API:

1. Use `POST /machines` to register the machine.
2. Use `GET /snmp-credentials` and copy the ID of `default-v2c`. This profile is
   created from the `SNMP_COMMUNITY` value on the first startup.
3. Use `PUT /machines/{mac}/snmp-credential` with the credential ID:

   ```json
   {"credential_id": "<credential-id>"}
   ```

4. Use `POST /machines/{mac}/snmp-credential/test` with `{}` as the body.
5. After one collection interval, check `GET /metrics/latest`.

For a machine outside OpenStack, include its MAC address:

```json
{
  "ipv4": "192.168.1.20",
  "mac": "aa:bb:cc:dd:ee:ff",
  "label": "web-01"
}
```

For an OpenStack machine, provide `ipv4` and optionally `label`; its MAC address
is discovered automatically.

To use SNMPv3, create a profile with `POST /snmp-credentials`, then bind and test
it in the same way. Secrets are accepted when creating or updating a profile but
are never returned by the API.

## Try the bundled SNMP agent

For a local smoke test, start the included agent. It uses the `public` community:

```bash
docker compose --profile snmp up -d snmpd
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.MacAddress}}{{end}}' "$(docker compose ps -q snmpd)"
```

Register the displayed IP and MAC as an external machine, then bind the
`default-v2c` credential as described above.

## Configure an SNMP agent

The default Debian/Ubuntu SNMP configuration does not expose all required
metrics. Install `snmpd`, then configure a read-only view in
`/etc/snmp/snmpd.conf`:

```text
view fleet included .1.3.6.1.2.1.1
view fleet included .1.3.6.1.2.1.2
view fleet included .1.3.6.1.2.1.25
view fleet included .1.3.6.1.2.1.31
view fleet included .1.3.6.1.4.1.2021.13.15

rocommunity your-community default -V fleet
```

Remove older `rocommunity` entries for the same community and restart `snmpd`.
Set `SNMP_COMMUNITY=your-community` before the API's first start, or create a new
SNMPv2c profile in the interactive API. SNMPv2c sends the community in clear
text; use SNMPv3 for production networks.

## Common commands

| Command | Purpose |
| --- | --- |
| `make up` | Start or rebuild the stack |
| `make ps` | Show service health |
| `make logs` | Follow API logs |
| `make restart` | Apply `.env` changes |
| `make down` | Stop services and keep data |
| `make clean` | Stop services and delete all local data |
| `make test` | Run the test suite (requires `uv`) |

## Troubleshooting

- **The API does not start:** check `make logs` and confirm all required `.env`
  values are set. If you are not using OpenStack, set
  `OPENSTACK_ENABLED=false`.
- **The credential test times out:** confirm UDP port 161 is reachable from the
  API container and that `snmpd` is listening on a non-loopback address.
- **The test succeeds but metrics are incomplete:** confirm the SNMP view includes
  all OIDs shown above. Disk I/O also requires the net-snmp disk I/O module.
- **No samples appear:** make sure the machine is enabled and has a credential
  bound, then inspect `GET /admin/collector` or run `make logs`.

API request and response details are available at <http://localhost:8000/docs>.
