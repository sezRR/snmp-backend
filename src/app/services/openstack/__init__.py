"""OpenStack lookup: protocol, in-memory TTL cache, factory.

OpenStack is the only source of truth for machine facts, so every read that
needs a tenant, user or flavor goes through here. That would mean an API call per
request, hence the cache: one fetch per TTL window, shared by every request,
flushable on demand from `/admin/openstack/cache/flush`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Protocol

from app.config import Settings
from app.models.openstack import CacheStats, ServerInfo

log = logging.getLogger(__name__)


class OpenStackLookup(Protocol):
    """The seam a real `openstack.connect()` client plugs into."""

    async def servers(self) -> list[ServerInfo]: ...


class CachedOpenStack:
    """TTL cache over an `OpenStackLookup`, with MAC and IPv4 indexes."""

    def __init__(self, upstream: OpenStackLookup, ttl_seconds: float) -> None:
        self._upstream = upstream
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()
        self._servers: list[ServerInfo] = []
        self._by_mac: dict[str, ServerInfo] = {}
        self._by_ipv4: dict[str, ServerInfo] = {}
        self._fetched_at: float | None = None
        self._hits = 0
        self._misses = 0
        self._refreshes = 0
        self._last_error: str | None = None

    # ---- internals ----------------------------------------------------------

    def _fresh(self) -> bool:
        return self._fetched_at is not None and (time.monotonic() - self._fetched_at) < self._ttl

    async def _ensure(self) -> None:
        if self._fresh():
            self._hits += 1
            return
        async with self._lock:
            # Another coroutine may have refreshed it while we waited for the
            # lock; without this check a cold cache would fan out one upstream
            # call per waiting request.
            if self._fresh():
                self._hits += 1
                return
            self._misses += 1
            try:
                servers = await self._upstream.servers()
            except Exception as exc:  # upstream is a network call
                self._last_error = f"{type(exc).__name__}: {exc}"
                log.warning("openstack lookup failed: %s", self._last_error)
                raise
            self._servers = servers
            self._by_mac = {normalise_mac(s.mac): s for s in servers}
            self._by_ipv4 = {s.ipv4: s for s in servers}
            self._fetched_at = time.monotonic()
            self._refreshes += 1
            self._last_error = None
            log.info("openstack lookup refreshed (%s servers)", len(servers))

    # ---- reads --------------------------------------------------------------

    async def servers(self) -> list[ServerInfo]:
        await self._ensure()
        return list(self._servers)

    async def by_mac(self, mac: str) -> ServerInfo | None:
        await self._ensure()
        return self._by_mac.get(normalise_mac(mac))

    async def by_ipv4(self, ipv4: str) -> ServerInfo | None:
        await self._ensure()
        return self._by_ipv4.get(ipv4)

    async def mac_index(self) -> dict[str, ServerInfo]:
        """Whole MAC index in one call, for the collector and list endpoints."""
        await self._ensure()
        return dict(self._by_mac)

    # ---- admin --------------------------------------------------------------

    def flush(self) -> int:
        dropped = len(self._servers)
        self._servers = []
        self._by_mac = {}
        self._by_ipv4 = {}
        self._fetched_at = None
        log.info("openstack cache flushed (%s servers dropped)", dropped)
        return dropped

    def stats(self) -> CacheStats:
        age = None
        fetched_at = None
        if self._fetched_at is not None:
            age = time.monotonic() - self._fetched_at
            fetched_at = datetime.fromtimestamp(
                time.time() - age, tz=timezone.utc
            ).isoformat()
        return CacheStats(
            ttl_seconds=self._ttl,
            populated=self._fetched_at is not None,
            fetched_at=fetched_at,
            age_seconds=age,
            servers=len(self._servers),
            hits=self._hits,
            misses=self._misses,
            refreshes=self._refreshes,
            last_error=self._last_error,
        )


def normalise_mac(mac: str) -> str:
    """Lowercase colon form, matching how Postgres renders `macaddr`.

    Clients and OpenStack both hand back MACs in whatever format they like;
    without this the cache index and the database disagree.
    """
    cleaned = mac.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if len(cleaned) != 12:
        return mac.strip().lower()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def build_lookup(settings: Settings) -> CachedOpenStack:
    if settings.openstack_simulate:
        from app.services.openstack.simulated import SimulatedOpenStack

        upstream: OpenStackLookup = SimulatedOpenStack()
        log.info("openstack: simulated fleet")
    else:  # pragma: no cover - needs openstacksdk and real credentials
        raise NotImplementedError(
            "Real OpenStack lookup not wired up yet: install openstacksdk, add an "
            "adapter implementing OpenStackLookup with openstack.connect(), and "
            "select it here. Set OPENSTACK_SIMULATE=true to use the fake fleet."
        )
    return CachedOpenStack(upstream, settings.openstack_cache_ttl_seconds)
