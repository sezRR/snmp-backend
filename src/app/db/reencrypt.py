from __future__ import annotations

import logging
import sys

from sqlalchemy.engine import Connection

from app.config import Settings, get_settings
from app.db import credentials as credentials_repo
from app.db.pool import Database
from app.security.crypto import CredentialCipher, CredentialCryptoError

log = logging.getLogger(__name__)


def reencrypt_blocking(conn: Connection, cipher: CredentialCipher) -> tuple[int, int]:
    """Rewrap every row not already on the active key. Returns (moved, skipped).

    One transaction for the whole run: a partial rotation is not a state worth
    persisting, and the row count here is small enough that holding the
    transaction costs nothing.
    """
    active = cipher.active_key_id
    moved = 0
    skipped = 0

    for row in credentials_repo.list_secrets(conn):
        if row["key_id"] == active:
            skipped += 1
            continue

        payload = cipher.decrypt(
            row["id"], row["secret_version"], row["key_id"], bytes(row["secret"])
        )
        secret, key_id = cipher.encrypt(row["id"], row["secret_version"], payload)
        credentials_repo.rewrap(
            conn, row["id"], secret, key_id, cipher.fingerprint(payload)
        )
        moved += 1
        log.info("rewrapped %r: %s -> %s", row["name"], row["key_id"], key_id)

    return moved, skipped


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    # Full `Settings`, unlike `app.db.migrate`: this one handles key material.
    settings: Settings = get_settings()
    cipher = CredentialCipher.from_settings(settings)
    if not cipher.usable:
        log.error(
            "no SNMP_CREDENTIAL_KEYS configured; nothing to re-encrypt with"
        )
        sys.exit(1)

    db = Database(settings)
    db.connect()
    try:
        with db.engine.begin() as conn:
            moved, skipped = reencrypt_blocking(conn, cipher)
    except CredentialCryptoError as exc:
        # Almost always the old key dropped from the ring too early.
        log.error("re-encryption aborted, nothing changed: %s", exc)
        sys.exit(1)
    finally:
        db.close()

    log.info(
        "re-encryption complete: %s moved onto %s, %s already there",
        moved,
        cipher.active_key_id,
        skipped,
    )


if __name__ == "__main__":
    main()
