#!/usr/bin/env python3
"""Register the simulated OpenStack fleet against a running API.

A fresh stack has an empty `machines` table, so the collector has nothing to
poll and every endpoint answers with an empty list — which looks like a bug the
first time you see it. This registers the fleet that
`app.services.openstack.simulated` serves, by address only: the MAC, tenant,
user and flavor all come from the lookup, exactly as they would for a real one.

`/machines` requires the `machines:write` scope, so this logs in first with
ADMIN_USERNAME / ADMIN_PASSWORD — the same values the backend was started with.

Registering is only half of it. A machine with no SNMP credential bound is not
polled at all — there is no fallback community string — so this then binds every
unbound machine to the `default-v2c` profile the backend seeds from
SNMP_COMMUNITY on its first boot. Binding is a separate call because it needs a
separate scope (`credentials:write`), which is the whole point of the split: see
`app.security.scopes`.

Run it inside the stack (`docker compose --profile seed run --rm seed`) or from
the host against the published port:

    API_BASE=http://127.0.0.1:8000 ADMIN_PASSWORD=... python scripts/seed_dev.py

Re-running is a no-op — an already registered machine answers 409.

Only the standard library, so it works in the app image with no extra
dependencies. That is also why the login below hand-rolls a form POST rather
than reaching for httpx.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000").rstrip("/")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# (address, label). Matches _FLEET in app/services/openstack/simulated.py; the
# labels are the client's own annotation, which is the one thing OpenStack does
# not supply.
FLEET = [
    ("10.0.0.11", "web-01"),
    ("10.0.0.12", "web-02"),
    ("10.0.0.13", "api-01"),
    ("10.0.0.14", "db-01"),
    ("10.0.1.21", "batch-01"),
    ("10.0.2.31", "gpu-01"),
]


def wait_for_api(attempts: int = 30, delay: float = 2.0) -> None:
    """`depends_on` already gates on health; this covers running from the host."""
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(f"{API_BASE}/readyz", timeout=3) as response:
                if response.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001 — any failure is "not up yet"
            if attempt == attempts:
                sys.exit(f"{API_BASE} never became ready: {exc}")
        time.sleep(delay)
    sys.exit(f"{API_BASE} never became ready")


def login() -> str:
    """Exchange the admin credentials for an access token.

    `/auth/login` is an OAuth2 password grant, so the body is form-encoded
    rather than JSON.
    """
    if not ADMIN_PASSWORD:
        sys.exit(
            "ADMIN_PASSWORD is not set. Use the same value the backend was "
            "started with — see .env.example."
        )
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
        }
    ).encode()
    request = urllib.request.Request(
        f"{API_BASE}/auth/login",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)["access_token"]
    except urllib.error.HTTPError as exc:
        sys.exit(
            f"could not log in as {ADMIN_USERNAME!r}: HTTP {exc.code} "
            f"{exc.read().decode(errors='replace')}"
        )


def call(method: str, path: str, token: str, body: dict | None = None):
    """One authenticated JSON call. Returns the decoded body, or raises."""
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{API_BASE}{path}", data=data, headers=headers, method=method
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status == 204:
            return None
        return json.load(response)


def register(ipv4: str, label: str, token: str) -> str:
    try:
        payload = call("POST", "/machines", token, {"ipv4": ipv4, "label": label})
        return f"registered {payload['mac']}"
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        if exc.code == 409:
            return "already registered"
        return f"HTTP {exc.code}: {detail}"


def default_credential_id(token: str) -> str | None:
    """The profile the backend seeded from SNMP_COMMUNITY, if it did."""
    try:
        for credential in call("GET", "/snmp-credentials", token):
            if credential["name"] == "default-v2c":
                return credential["id"]
    except urllib.error.HTTPError as exc:
        print(f"could not list credentials: HTTP {exc.code}")
    return None


def bind_unbound(token: str) -> int:
    """Bind every machine that has no credential. Returns how many were bound.

    Re-runnable: a machine that is already bound is skipped, so this does not
    undo a deliberate binding to some other profile.
    """
    credential_id = default_credential_id(token)
    if credential_id is None:
        print(
            "\nno `default-v2c` credential: the backend was started without "
            "SNMP_CREDENTIAL_KEYS, so nothing can be bound and nothing will be "
            "polled. Set it in .env and restart — see .env.example."
        )
        return 0

    bound = 0
    for machine in call("GET", "/machines", token):
        if machine["credential_id"] is not None:
            continue
        try:
            call(
                "PUT",
                f"/machines/{machine['mac']}/snmp-credential",
                token,
                {"credential_id": credential_id},
            )
            bound += 1
        except urllib.error.HTTPError as exc:
            print(f"could not bind {machine['mac']}: HTTP {exc.code}")
    return bound


def main() -> int:
    # /readyz stays public, so this still works before authenticating.
    wait_for_api()
    token = login()
    failures = 0
    for ipv4, label in FLEET:
        outcome = register(ipv4, label, token)
        if outcome.startswith("HTTP"):
            failures += 1
        print(f"{label:<10} {ipv4:<12} {outcome}")
    print(f"\n{len(FLEET) - failures}/{len(FLEET)} machines present at {API_BASE}")
    print(f"{bind_unbound(token)} machine(s) bound to default-v2c")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
