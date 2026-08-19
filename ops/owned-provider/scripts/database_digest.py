"""Compute a deterministic, bounded-memory semantic digest of every application table."""

from __future__ import annotations

import argparse
import hashlib
import json
from sqlalchemy import text

from app.db import Session
from server import create_light_app

MAIL_EDGE_HOST_TABLES = frozenset(
    {
        "mail_edge_replay_nonce",
        "mail_edge_callback_receipt",
        "mail_edge_outbound_projection",
        "mail_edge_route_binding_projection",
    }
)


def digest_database(*, legacy_pre_mail_edge: bool = False) -> dict:
    tables = Session.execute(
        text(
            """
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_type='BASE TABLE' AND table_schema IN ('public', 'owned_provider')
        ORDER BY table_schema, table_name
        """
        )
    ).fetchall()
    observed_mail_edge_tables = {
        table
        for schema, table in tables
        if schema == "public" and table.startswith("mail_edge_")
    }
    expected_mail_edge_tables = (
        frozenset() if legacy_pre_mail_edge else MAIL_EDGE_HOST_TABLES
    )
    if observed_mail_edge_tables != expected_mail_edge_tables:
        raise RuntimeError(
            "Mail Edge host table inventory differs: "
            f"expected={sorted(expected_mail_edge_tables)!r}, "
            f"observed={sorted(observed_mail_edge_tables)!r}"
        )
    table_results = []
    overall = hashlib.sha256()
    for schema, table in tables:
        if (
            not schema.replace("_", "").isalnum()
            or not table.replace("_", "").isalnum()
        ):
            raise RuntimeError("unexpected SQL identifier")
        table_hash = hashlib.sha256()
        count = 0
        query = (
            f'SELECT to_jsonb(row_value)::text FROM "{schema}"."{table}" row_value '
            'ORDER BY (to_jsonb(row_value)::text) COLLATE "C"'
        )
        result = Session.execute(text(query))
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
        text(
            """
        SELECT schemaname, sequencename, coalesce(last_value::text, 'NULL')
        FROM pg_sequences
        WHERE schemaname IN ('public', 'owned_provider')
        ORDER BY schemaname, sequencename
        """
        )
    ).fetchall()
    sequence_rows = [list(item) for item in sequences]
    overall.update(
        json.dumps(sequence_rows, sort_keys=True, separators=(",", ":")).encode()
    )
    digest = {
        "format": "simplelogin-owned-provider-database-digest",
        "format_version": 1 if legacy_pre_mail_edge else 2,
        "sha256": overall.hexdigest(),
        "tables": table_results,
        "sequences": sequence_rows,
    }
    if not legacy_pre_mail_edge:
        digest["mail_edge_host_tables"] = sorted(observed_mail_edge_tables)
    return digest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--legacy-pre-mail-edge",
        action="store_true",
        help="require the pre-Mail-Edge table inventory and emit digest format 1",
    )
    args = parser.parse_args()
    with create_light_app().app_context():
        print(
            json.dumps(
                digest_database(legacy_pre_mail_edge=args.legacy_pre_mail_edge),
                sort_keys=True,
            )
        )
