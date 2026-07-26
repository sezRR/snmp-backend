"""Application entrypoint: `uvicorn app.main:app`."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routers import admin, health, machines, metrics, stream
from app.config import Settings, get_settings
from app.db.init import apply_schema
from app.db.pool import Database
from app.services.bus import MetricBus
from app.services.collector import Collector
from app.services.openstack import build_lookup
from app.services.snmp import build_sampler

log = logging.getLogger(__name__)


def configure_logging(settings: Settings) -> None:
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    configure_logging(settings)

    if settings.db_auto_init:
        # Retries internally: on a cold cluster this pod is usually up before
        # Postgres has finished initdb.
        await apply_schema(settings)

    db = Database(settings)
    db.connect()
    app.state.db = db

    app.state.bus = MetricBus(queue_maxsize=settings.sse_queue_maxsize)
    app.state.lookup = build_lookup(settings)
    # The simulated sampler sizes each host from its OpenStack flavor, so its
    # reported cores/RAM/disk agree with what /machines returns.
    app.state.sampler = build_sampler(settings, lookup=app.state.lookup)
    app.state.collector = Collector(
        settings=settings,
        db=db,
        sampler=app.state.sampler,
        lookup=app.state.lookup,
        bus=app.state.bus,
    )
    if settings.collector_enabled:
        app.state.collector.start()

    try:
        yield
    finally:
        await app.state.collector.stop()
        db.close()
        app.state.db = None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title="SNMP metrics API",
        version=__version__,
        summary="Polls SNMP metrics into TimescaleDB; OpenStack is the source of truth for machine facts.",
        # Traefik strips /api before the request arrives; root_path puts the
        # prefix back into the docs and OpenAPI `servers` URLs.
        root_path=settings.root_path,
        lifespan=lifespan,
    )

    origins = [
        "http://localhost:5173",  # Vite / Vue local development port
        "http://localhost:4173",  # Vite / Vue local development port
        "http://192.168.1.115",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,  # Allowed domains
        allow_credentials=True,  # Support cookies & authentication headers
        allow_methods=["*"],  # Allow all standard HTTP methods (GET, POST, etc.)
        allow_headers=["*"],  # Allow all custom request headers
    )

    app.state.settings = settings

    app.include_router(health.router)
    app.include_router(machines.router)
    app.include_router(metrics.router)
    app.include_router(stream.router)
    app.include_router(admin.router)

    @app.get("/", tags=["health"])
    async def root() -> dict[str, object]:
        return {
            "service": "snmp-metrics-api",
            "version": __version__,
            "docs": f"{settings.root_path}/docs",
            "collector_interval_seconds": settings.collector_interval_seconds,
            "simulated": {
                "snmp": settings.snmp_simulate,
                "openstack": settings.openstack_simulate,
            },
        }

    return app


app = create_app()
