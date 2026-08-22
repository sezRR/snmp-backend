from __future__ import annotations

from enum import StrEnum


class Scope(StrEnum):
    MACHINES_READ = "machines:read"
    MACHINES_WRITE = "machines:write"
    METRICS_READ = "metrics:read"
    METRICS_WRITE = "metrics:write"
    ADMIN_READ = "admin:read"
    ADMIN_WRITE = "admin:write"
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    ROLES_READ = "roles:read"
    ROLES_WRITE = "roles:write"
    CREDENTIALS_READ = "credentials:read"
    CREDENTIALS_WRITE = "credentials:write"


ALL_SCOPES: frozenset[str] = frozenset(str(s) for s in Scope)

# Shown in Swagger's Authorize dialog and returned by GET /scopes.
SCOPE_DESCRIPTIONS: dict[str, str] = {
    Scope.MACHINES_READ: "List and read registered machines",
    Scope.MACHINES_WRITE: "Register, patch and deregister machines",
    Scope.METRICS_READ: "Read metric history, aggregates and live streams",
    Scope.METRICS_WRITE: "Purge metric history",
    Scope.ADMIN_READ: "Read collector and OpenStack cache state",
    Scope.ADMIN_WRITE: "Force collector ticks and flush the OpenStack cache",
    Scope.USERS_READ: "List and read user accounts",
    Scope.USERS_WRITE: "Create, edit and delete users, and assign their roles",
    Scope.ROLES_READ: "List and read roles and the scopes they hold",
    Scope.ROLES_WRITE: "Create, edit and delete roles",
    Scope.CREDENTIALS_READ: "List and read SNMP credential profiles (never their secrets)",
    Scope.CREDENTIALS_WRITE: (
        "Create, edit and delete SNMP credentials, and bind them to machines"
    ),
}

ADMIN_ROLE_NAME = "admin"

# The scope that mints more admins: losing every holder is unrecoverable.
ADMIN_GATE_SCOPE = str(Scope.USERS_WRITE)

# `credentials:write` is a security boundary, not tidiness: binding a shared
# credential decides which host the collector authenticates to with a
# fleet-wide secret, and a hostile agent can attack that exchange offline.
# Registering is the low-privilege half, binding the high-privilege one.


def unknown_scopes(candidates: list[str]) -> list[str]:
    """The candidates that are not real scopes, in the order they were given."""
    return [s for s in candidates if s not in ALL_SCOPES]
