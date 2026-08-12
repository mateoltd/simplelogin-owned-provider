"""Apply the owned-provider operational schema without touching upstream migrations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.db import Session
from server import create_light_app


MIGRATIONS = Path("/code/ops/owned-provider/migrations")
LOCK_ID = 7_329_461_005


def migrate() -> dict:
    Session.execute("SELECT pg_advisory_lock(:lock)", {"lock": LOCK_ID})
    try:
        Session.execute("CREATE SCHEMA IF NOT EXISTS owned_provider")
        Session.execute(
            """
            CREATE TABLE IF NOT EXISTS owned_provider.schema_migration (
                name text PRIMARY KEY,
                sha256 text NOT NULL,
                applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
            )
            """
        )
        Session.commit()
        applied = []
        for path in sorted(MIGRATIONS.glob("*.sql")):
            body = path.read_bytes()
            digest = hashlib.sha256(body).hexdigest()
            existing = Session.execute(
                "SELECT sha256 FROM owned_provider.schema_migration WHERE name=:name",
                {"name": path.name},
            ).scalar()
            if existing:
                if existing != digest:
                    raise RuntimeError(f"applied migration changed: {path.name}")
                continue
            Session.execute(body.decode())
            Session.execute(
                "INSERT INTO owned_provider.schema_migration(name, sha256) VALUES (:name, :sha256)",
                {"name": path.name, "sha256": digest},
            )
            Session.commit()
            applied.append(path.name)
        count = Session.execute(
            "SELECT count(*) FROM owned_provider.schema_migration"
        ).scalar()
        return {"applied": applied, "migration_count": count}
    finally:
        Session.execute("SELECT pg_advisory_unlock(:lock)", {"lock": LOCK_ID})
        Session.commit()


if __name__ == "__main__":
    with create_light_app().app_context():
        print(json.dumps(migrate(), sort_keys=True))
