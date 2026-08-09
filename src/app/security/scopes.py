"""The permission vocabulary.

Scopes are fixed in code and have no table. They name capabilities the API
actually implements, so the set can only change when a deployment adds or
removes an endpoint — a catalogue table would be a second source of truth with
nothing to say that this file does not, and one more thing that could disagree.

Roles, by contrast, *are* data: an admin composes them out of these scopes
through `/roles`, and `role_scopes` records the result. Scope strings coming in
over HTTP are validated against `Scope` on write, so a typo is a 422 rather than
a grant that silently never matches.

`admin` is not special-cased anywhere in the checker. It is an ordinary role
that happens to hold every scope, reconciled on each boot by
`app.services.bootstrap` — which means a scope added to this enum lands on the
admin role at the next restart, with no migration and no data edit.
"""

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


ALL_SCOPES: frozenset[str] = frozenset(str(s) for s in Scope)

# Shown in Swagger's Authorize dialog and returned by GET /scopes, which is what
# a role-editing UI would build its checkboxes from.
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
}

ADMIN_ROLE_NAME = "admin"

# The scope that can mint more admins. Losing every holder of it is the one
# unrecoverable state, so the user and role endpoints guard it specifically.
ADMIN_GATE_SCOPE = str(Scope.USERS_WRITE)


def unknown_scopes(candidates: list[str]) -> list[str]:
    """The candidates that are not real scopes, in the order they were given."""
    return [s for s in candidates if s not in ALL_SCOPES]
