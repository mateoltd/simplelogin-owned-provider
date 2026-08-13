from __future__ import annotations

import sqlite3

import pytest

from mail_edge.blob import LocalEncryptedBlobStore
from mail_edge.db import Database, migrate, migration_status, sqlite_url
from mail_edge.errors import BlobIntegrityError, ConfigurationError, DuplicateConflict


def test_migrations_are_complete_idempotent_and_checksummed(tmp_path):
    database = Database(sqlite_url(tmp_path / "edge.sqlite"))
    assert migrate(database) == ["0001_initial", "0002_route_immutability"]
    assert migrate(database) == []
    assert migration_status(database) == (
        ["0001_initial", "0002_route_immutability"],
        ["0001_initial", "0002_route_immutability"],
    )
    with database.transaction(immediate=True) as connection:
        connection.execute(
            "UPDATE mail_edge_schema_migrations SET checksum = ?",
            ("0" * 64,),
        )
    with pytest.raises(ConfigurationError, match="checksum changed"):
        migrate(database)


def test_migration_constraints_reject_invalid_states(edge):
    with (
        edge["database"].transaction(immediate=True) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            """
            INSERT INTO route_generations(
                id, domain, direction, generation, provider, state,
                provider_config, qualified_policy_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "bad",
                "aliases.example",
                "sideways",
                0,
                "mailgun",
                "magic",
                "{}",
                "v1",
                "now",
                "now",
            ),
        )


def test_blob_is_encrypted_authenticated_and_idempotent(tmp_path):
    store = LocalEncryptedBlobStore(tmp_path / "blob", {"key-a": b"a" * 32}, "key-a")
    plaintext = b"From: private@example.test\r\n\r\nsecret body"
    record = store.put("inbound/message/raw", plaintext)
    encoded = (tmp_path / "blob/inbound/message/raw.meb").read_bytes()
    assert plaintext not in encoded
    assert b"private@example.test" not in encoded
    assert store.get(record.blob_id) == plaintext
    assert store.put(record.blob_id, plaintext) == record
    with pytest.raises(DuplicateConflict):
        store.put(record.blob_id, b"different")


def test_blob_tamper_and_wrong_key_fail_closed(tmp_path):
    root = tmp_path / "blob"
    store = LocalEncryptedBlobStore(root, {"key-a": b"a" * 32}, "key-a")
    store.put("outbound/message/raw", b"payload")
    path = root / "outbound/message/raw.meb"
    encoded = bytearray(path.read_bytes())
    encoded[-1] ^= 1
    path.write_bytes(encoded)
    with pytest.raises(BlobIntegrityError, match="authentication failed"):
        store.get("outbound/message/raw")
    unavailable = LocalEncryptedBlobStore(root, {"key-b": b"b" * 32}, "key-b")
    with pytest.raises(BlobIntegrityError, match="unavailable"):
        unavailable.get("outbound/message/raw")


def test_blob_paths_cannot_escape(tmp_path):
    store = LocalEncryptedBlobStore(tmp_path / "blob", {"key-a": b"a" * 32}, "key-a")
    with pytest.raises(ValueError):
        store.put("../escape", b"payload")
