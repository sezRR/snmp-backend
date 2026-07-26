"""Liveness and readiness.

Split on purpose: `/healthz` touches nothing, so a database outage never gets the
container restarted, while `/readyz` queries Postgres, so the pod leaves the
Service endpoints for as long as it cannot serve data.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from app.api.deps import DbDep

log = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(db: DbDep) -> dict[str, str | None]:
    try:
        version = await db.healthcheck()
    except Exception as exc:
        log.warning("readiness check failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"database unavailable: {exc}",
        ) from exc
    return {"status": "ok", "timescaledb": version}
