"""Request-scoped accessors for the objects built in the lifespan.

They live on `app.state`, so these exist to keep `request.app.state.…` and its
`RuntimeError` handling out of every endpoint.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from app.config import Settings, get_settings
from app.db.pool import Database
from app.services.bus import MetricBus
from app.services.collector import Collector
from app.services.openstack import CachedOpenStack


def get_db(request: Request) -> Database:
    db: Database | None = getattr(request.app.state, "db", None)
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database pool is not open",
        )
    return db


def get_lookup(request: Request) -> CachedOpenStack:
    return request.app.state.lookup


def get_bus(request: Request) -> MetricBus:
    return request.app.state.bus


def get_collector(request: Request) -> Collector:
    return request.app.state.collector


DbDep = Annotated[Database, Depends(get_db)]
LookupDep = Annotated[CachedOpenStack, Depends(get_lookup)]
BusDep = Annotated[MetricBus, Depends(get_bus)]
CollectorDep = Annotated[Collector, Depends(get_collector)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
