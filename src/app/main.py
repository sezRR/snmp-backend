"""Application entrypoint: `uvicorn app.main:app`."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routers import (
    admin,
    auth,
    credentials,
    health,
    machines,
    metrics,
    roles,
    stream,
    users,
)
from app.api.security import StreamTickets
from app.config import Settings, get_settings
from app.db.migrate import run_migrations
from app.db.policies import apply_policies
from app.db.pool import Database
from app.security.crypto import CredentialCipher
from app.services.bootstrap import bootstrap_admin, bootstrap_credentials
from app.services.bus import MetricBus
from app.services.sessions import SessionEpochs
from app.services.collector import Collector
from app.services.credentials import CredentialCache
from app.services.openstack import build_lookup
from app.services.ratelimit import LoginRateLimiter
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

    db = Database(settings)
    db.connect()
    app.state.db = db
    lookup = None
    collector = None
    try:
        if settings.db_auto_migrate:
            # Retries internally because Postgres may still be finishing initdb.
            # Also takes an advisory lock, so processes starting together do not
            # race each other through the same revision.
            await run_migrations(db.engine, settings)

        # Not schema, and so not Alembic's: both windows are settings, re-applied on
        # every boot so the configuration stays authoritative.
        await apply_policies(db.engine, settings)

        # Raises if it cannot guarantee an administrator, which aborts startup. An
        # API with permissions enforced everywhere and nobody holding them is worse
        # than one that refuses to come up.
        await bootstrap_admin(db, settings)

        app.state.cipher = CredentialCipher.from_settings(settings)
        # Seeds the default v2c profile from SNMP_COMMUNITY on the first boot that
        # finds none, and binds the machines that predate credentials. Not a
        # migration: Alembic runs without the key ring, and this needs to encrypt.
        await bootstrap_credentials(db, settings, app.state.cipher)
        app.state.credentials = CredentialCache(db, app.state.cipher)

        app.state.bus = MetricBus(queue_maxsize=settings.sse_queue_maxsize)
        # In-process, like the bus a stream reads from.
        app.state.stream_tickets = StreamTickets(settings.stream_ticket_ttl_seconds)
        # A cache, not a source of truth: users.session_epoch is, and a token
        # that disagrees with what is cached is checked against the row itself.
        app.state.session_epochs = SessionEpochs(
            db, settings.session_epoch_cache_ttl_seconds
        )
        # Also per-process: with more than one each carries its own counters, so
        # the effective limit is multiplied by the process count.
        app.state.login_limiter = LoginRateLimiter(
            max_per_user=settings.login_rate_limit_max_per_user,
            max_per_ip=settings.login_rate_limit_max_per_ip,
            window_seconds=settings.login_rate_limit_window_seconds,
            enabled=settings.login_rate_limit_enabled,
        )
        lookup = build_lookup(settings)
        app.state.lookup = lookup
        app.state.sampler = build_sampler(settings)
        collector = Collector(
            settings=settings,
            db=db,
            sampler=app.state.sampler,
            lookup=lookup,
            bus=app.state.bus,
            credentials=app.state.credentials,
        )
        app.state.collector = collector
        if settings.collector_enabled:
            collector.start()

        yield
    finally:
        try:
            if collector is not None:
                await collector.stop()
        finally:
            try:
                if lookup is not None:
                    lookup.close()
            finally:
                db.close()
                app.state.db = None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title="SNMP metrics API",
        version=__version__,
        summary="Polls SNMP metrics into TimescaleDB; OpenStack is the source of truth for machine facts.",
        # root_path restores a prefix stripped by an optional reverse proxy.
        root_path=settings.root_path,
        lifespan=lifespan,
    )

    # CORS_ALLOW_ORIGINS, comma separated. Exact matches only — scheme, host and
    # port all count.
    origins = settings.allowed_origins
    if "*" in origins:
        # Starlette answers a credentialed request by echoing the caller's own
        # origin rather than a literal `*`, so this is not "no CORS" — it is
        # "every site is trusted with the user's cookies". Log it loudly.
        log.warning(
            "CORS_ALLOW_ORIGINS contains '*' while credentials are allowed; "
            "any origin can make authenticated requests. List real origins instead."
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,  # Allowed domains
        allow_credentials=True,  # Support cookies & authentication headers
        allow_methods=["*"],  # Allow all standard HTTP methods (GET, POST, etc.)
        allow_headers=["*"],  # Allow all custom request headers
        # A browser cannot read a response header it was not handed. These two
        # carry what `/metrics/stats` resolved a request to — the bucket width
        # after fitting and flooring, and the table it was answered from — which
        # a chart needs to label itself.
        expose_headers=["X-Metrics-Bucket", "X-Metrics-Source"],
    )

    app.state.settings = settings

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(roles.router)
    app.include_router(machines.router)
    app.include_router(credentials.router)
    # Same /machines prefix as the machines router, carrying the credential
    # sub-resource. Separate because its routes are gated on credentials:write.
    app.include_router(credentials.machine_router)
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
        }

    return app


app = create_app()
