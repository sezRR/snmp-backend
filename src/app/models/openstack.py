from __future__ import annotations

from pydantic import BaseModel, Field


class FlavorInfo(BaseModel):
    name: str
    vcpus: int
    ram_mb: int
    disk_gb: int


class ServerInfo(BaseModel):
    """What OpenStack knows about a server.

    Never persisted — looked up per request so it cannot go stale against the
    real fleet. `mac` and `ipv4` are the join keys onto our `machines` table.

    `subnet_name` is descriptive only. It comes from Neutron rather than Nova,
    so it is None whenever the port or subnet behind `ipv4` is not readable —
    losing a label must not cost us a server record.
    """

    server_id: str
    name: str
    tenant_name: str
    user_name: str
    status: str
    mac: str
    ipv4: str
    subnet_name: str | None = None
    flavor: FlavorInfo


class CacheStats(BaseModel):
    ttl_seconds: float
    populated: bool
    fetched_at: str | None = None
    age_seconds: float | None = None
    servers: int = 0
    hits: int = 0
    misses: int = 0
    refreshes: int = 0
    last_error: str | None = None


class CacheFlushed(BaseModel):
    flushed: bool = True
    dropped_servers: int = Field(
        description="How many cached server records were discarded"
    )
