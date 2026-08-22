#!/usr/bin/env python3
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

# (address, label). Each address must be one OpenStack knows about, since the
# MAC and tenant are read from the lookup at registration time. The labels are
# the client's own annotation, which is the one thing OpenStack does not supply.
FLEET = [
    ("10.0.0.11", "web-01"),
    ("10.0.0.12", "web-02"),
    ("10.0.0.13", "api-01"),
    ("10.0.0.14", "db-01"),
    ("10.0.1.21", "batch-01"),
    ("10.0.2.31", "gpu-01"),
]


def wait_for_api(attempts: int = 30, delay: float = 2.0) -> None:
    """Wait through startup for host runs and manual container execution."""
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
            "polled. Set it in .env and recreate the API container — see "
            ".env.example."
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
    if sys.argv[1:] == ["--token"]:
        wait_for_api()
        print(login())
        return 0
    if sys.argv[1:]:
        sys.exit("usage: seed_dev.py [--token]")

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
