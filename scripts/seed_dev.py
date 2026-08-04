#!/usr/bin/env python3
"""Register the simulated OpenStack fleet against a running API.

A fresh stack has an empty `machines` table, so the collector has nothing to
poll and every endpoint answers with an empty list — which looks like a bug the
first time you see it. This registers the fleet that
`app.services.openstack.simulated` serves, by address only: the MAC, tenant,
user and flavor all come from the lookup, exactly as they would for a real one.

Run it inside the stack (`docker compose --profile seed run --rm seed`) or from
the host against the published port:

    API_BASE=http://127.0.0.1:8000 python scripts/seed_dev.py

Re-running is a no-op — an already registered machine answers 409.

Only the standard library, so it works in the app image with no extra
dependencies.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000").rstrip("/")

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


def register(ipv4: str, label: str) -> str:
    body = json.dumps({"ipv4": ipv4, "label": label}).encode()
    request = urllib.request.Request(
        f"{API_BASE}/machines",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.load(response)
            return f"registered {payload['mac']}"
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        if exc.code == 409:
            return "already registered"
        return f"HTTP {exc.code}: {detail}"


def main() -> int:
    wait_for_api()
    failures = 0
    for ipv4, label in FLEET:
        outcome = register(ipv4, label)
        if outcome.startswith("HTTP"):
            failures += 1
        print(f"{label:<10} {ipv4:<12} {outcome}")
    print(f"\n{len(FLEET) - failures}/{len(FLEET)} machines present at {API_BASE}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
