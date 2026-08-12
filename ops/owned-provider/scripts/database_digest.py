"""Compute a deterministic, bounded-memory semantic digest of every application table."""

from __future__ import annotations

import hashlib
import json

from app.db import Session
from server import create_light_app


def digest_database() -> dict:
    tables = Session.execute(
        """
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_type='BASE TABLE' AND table_schema IN ('public', 'owned_provider')
        ORDER BY table_schema, table_name
        """
    ).fetchall()
    table_results = []
    overall = hashlib.sha256()
    for schema, table in tables:
        if not schema.replace("_", "").isalnum() or not table.replace("_", "").isalnum():
            raise RuntimeError("unexpected SQL identifier")
        table_hash = hashlib.sha256()
        count = 0
        query = (
            f'SELECT to_jsonb(row_value)::text FROM "{schema}"."{table}" row_value '
            'ORDER BY (to_jsonb(row_value)::text) COLLATE "C"'
        )
        result = Session.execute(query)
        while rows := result.fetchmany(1000):
            for (row,) in rows:
                encoded = (row + "\n").encode()
                table_hash.update(encoded)
                count += 1
        item = {
            "schema": schema,
            "table": table,
            "rows": count,
            "sha256": table_hash.hexdigest(),
        }
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
        overall.update(canonical + b"\n")
        table_results.append(item)
    sequences = Session.execute(
        """
        SELECT schemaname, sequencename, coalesce(last_value::text, 'NULL')
        FROM pg_sequences
        WHERE schemaname IN ('public', 'owned_provider')
        ORDER BY schemaname, sequencename
        """
    ).fetchall()
    sequence_rows = [list(item) for item in sequences]
    overall.update(
        json.dumps(sequence_rows, sort_keys=True, separators=(",", ":")).encode()
    )
    return {
        "format": "simplelogin-owned-provider-database-digest",
        "format_version": 1,
        "sha256": overall.hexdigest(),
        "tables": table_results,
        "sequences": sequence_rows,
    }


if __name__ == "__main__":
    with create_light_app().app_context():
        print(json.dumps(digest_database(), sort_keys=True))
