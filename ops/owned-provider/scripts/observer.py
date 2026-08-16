"""Dependency-aware readiness and bounded-cardinality Prometheus metrics."""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import redis
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from app.db import Session
from app.models import JobState
from server import create_light_app

APP = create_light_app()
STARTED = time.monotonic()
UPSTREAM = (
    open("/code/ops/owned-provider/UPSTREAM_COMMIT", encoding="utf-8").read().strip()
)


def scalar(sql: str, params=None):
    return Session.execute(text(sql), params or {}).scalar()


def collect() -> dict:
    started = time.monotonic()
    result = {
        "http": False,
        "mail_edge": None,
        "postgres": False,
        "redis": False,
        "migration_at_head": False,
        "migration_current": None,
        "migration_expected": None,
        "counts": {},
        "jobs": {},
        "synthetic": {"success": None, "age_seconds": None},
        "backup": {"success": None, "age_seconds": None, "size_bytes": None},
        "resources": {},
        "error": None,
    }
    try:
        with urllib.request.urlopen("http://app:7777/health", timeout=3) as response:
            result["http"] = response.status == 200 and response.read() == b"success"
        if os.environ.get("MAIL_EDGE_CONFIG_PATH"):
            try:
                with urllib.request.urlopen(
                    "http://app:7777/health/mail-edge/readyz", timeout=5
                ) as response:
                    result["mail_edge"] = response.status == 200
                    response.read(1_048_577)
            except (OSError, urllib.error.HTTPError):
                result["mail_edge"] = False
        redis_client = redis.Redis.from_url(
            os.environ["MEM_STORE_URI"], socket_timeout=2
        )
        try:
            result["redis"] = bool(redis_client.ping())
            redis_info = redis_client.info("memory")
        finally:
            redis_client.close()
        result["resources"]["redis_used_memory_bytes"] = int(
            redis_info.get("used_memory", 0)
        )
        with APP.app_context():
            result["postgres"] = scalar("SELECT 1") == 1
            current = scalar("SELECT version_num FROM alembic_version")
            expected = ScriptDirectory.from_config(
                Config("alembic.ini")
            ).get_current_head()
            result["migration_current"] = current
            result["migration_expected"] = expected
            result["migration_at_head"] = current == expected
            for name in ("alias", "mailbox", "custom_domain", "contact", "email_log"):
                result["counts"][name] = scalar(f'SELECT count(*) FROM "{name}"')
            for name in (
                "mail_edge_replay_nonce",
                "mail_edge_callback_receipt",
                "mail_edge_outbound_projection",
                "mail_edge_route_binding_projection",
            ):
                result["counts"][name] = scalar(f'SELECT count(*) FROM "{name}"')
            result["counts"]["mail_edge_callback_processing"] = scalar(
                "SELECT count(*) FROM mail_edge_callback_receipt WHERE status='processing'"
            )
            result["counts"]["mail_edge_outbound_quarantined"] = scalar(
                "SELECT count(*) FROM mail_edge_outbound_projection WHERE quarantined"
            )
            for label, state in (
                ("ready", JobState.ready.value),
                ("taken", JobState.taken.value),
                ("done", JobState.done.value),
                ("error", JobState.error.value),
            ):
                result["jobs"][label] = scalar(
                    "SELECT count(*) FROM job WHERE state=:state", {"state": state}
                )
            result["jobs"]["oldest_ready_seconds"] = float(
                scalar(
                    """
                    SELECT coalesce(extract(epoch FROM clock_timestamp() - min(created_at)), 0)
                    FROM job WHERE state=:state
                    """,
                    {"state": JobState.ready.value},
                )
                or 0
            )
            result["jobs"]["oldest_taken_seconds"] = float(
                scalar(
                    """
                    SELECT coalesce(extract(epoch FROM clock_timestamp() - min(taken_at)), 0)
                    FROM job WHERE state=:state
                    """,
                    {"state": JobState.taken.value},
                )
                or 0
            )
            probe = Session.execute(text("""
                SELECT success, extract(epoch FROM clock_timestamp() - checked_at)
                FROM owned_provider.probe_result
                WHERE probe_name='api-smtp'
                ORDER BY checked_at DESC LIMIT 1
                """)).first()
            if probe:
                result["synthetic"] = {
                    "success": bool(probe[0]),
                    "age_seconds": max(0.0, float(probe[1])),
                }
            backup = Session.execute(text("""
                SELECT success, extract(epoch FROM clock_timestamp() - completed_at), size_bytes
                FROM owned_provider.backup_result
                ORDER BY completed_at DESC LIMIT 1
                """)).first()
            if backup:
                result["backup"] = {
                    "success": bool(backup[0]),
                    "age_seconds": max(0.0, float(backup[1])),
                    "size_bytes": int(backup[2]),
                }
            result["resources"]["postgres_database_bytes"] = int(
                scalar("SELECT pg_database_size(current_database())")
            )
            result["resources"]["postgres_connections"] = int(
                scalar("SELECT count(*) FROM pg_stat_activity")
            )
        result["resources"]["volume_available_bytes"] = shutil.disk_usage(
            "/code/static/upload"
        ).free
        result["resources"]["mail_edge_spool_available_bytes"] = shutil.disk_usage(
            "/code/var/mail-edge-spool"
        ).free
    except Exception as error:
        Session.rollback()
        result["error"] = f"{type(error).__name__}: {error}"[:300]
    result["latency_ms"] = round((time.monotonic() - started) * 1000, 3)
    stale_limit = int(os.environ.get("OWNED_PROVIDER_JOB_STALE_SECONDS", "2100"))
    result["ready"] = all(
        (
            result["http"],
            result["postgres"],
            result["redis"],
            result["migration_at_head"],
            result["mail_edge"] is not False,
            result["jobs"].get("oldest_taken_seconds", stale_limit + 1) <= stale_limit,
        )
    )
    return result


def metrics(data: dict) -> str:
    lines = [
        "# HELP owned_provider_ready Whether API dependencies and migrations are ready.",
        "# TYPE owned_provider_ready gauge",
        f"owned_provider_ready {int(data['ready'])}",
        "# HELP owned_provider_dependency_up Whether a required dependency is up.",
        "# TYPE owned_provider_dependency_up gauge",
    ]
    for dependency in ("http", "postgres", "redis", "mail_edge"):
        if data[dependency] is None:
            continue
        lines.append(
            f'owned_provider_dependency_up{{dependency="{dependency}"}} {int(data[dependency])}'
        )
    lines.extend(
        [
            "# HELP owned_provider_objects Current durable object counts.",
            "# TYPE owned_provider_objects gauge",
        ]
    )
    for kind, count in sorted(data["counts"].items()):
        lines.append(f'owned_provider_objects{{kind="{kind}"}} {count}')
    lines.extend(
        [
            "# HELP owned_provider_jobs Current job counts by state.",
            "# TYPE owned_provider_jobs gauge",
        ]
    )
    for state in ("ready", "taken", "done", "error"):
        lines.append(
            f'owned_provider_jobs{{state="{state}"}} {data["jobs"].get(state, 0)}'
        )
    lines.extend(
        [
            "# HELP owned_provider_job_oldest_seconds Age of the oldest queued or taken job.",
            "# TYPE owned_provider_job_oldest_seconds gauge",
            f'owned_provider_job_oldest_seconds{{state="ready"}} {data["jobs"].get("oldest_ready_seconds", 0)}',
            f'owned_provider_job_oldest_seconds{{state="taken"}} {data["jobs"].get("oldest_taken_seconds", 0)}',
            "# HELP owned_provider_synthetic_success Last API and SMTP synthetic result.",
            "# TYPE owned_provider_synthetic_success gauge",
            f"owned_provider_synthetic_success {int(bool(data['synthetic']['success']))}",
            "# HELP owned_provider_synthetic_age_seconds Age of the last synthetic result.",
            "# TYPE owned_provider_synthetic_age_seconds gauge",
            f"owned_provider_synthetic_age_seconds {data['synthetic']['age_seconds'] or 0}",
            "# HELP owned_provider_backup_success Last encrypted backup result.",
            "# TYPE owned_provider_backup_success gauge",
            f"owned_provider_backup_success {int(bool(data['backup']['success']))}",
            "# HELP owned_provider_backup_age_seconds Age of the last encrypted backup.",
            "# TYPE owned_provider_backup_age_seconds gauge",
            f"owned_provider_backup_age_seconds {data['backup']['age_seconds'] or 0}",
            "# HELP owned_provider_backup_size_bytes Size of the last encrypted backup.",
            "# TYPE owned_provider_backup_size_bytes gauge",
            f"owned_provider_backup_size_bytes {data['backup']['size_bytes'] or 0}",
            "# HELP owned_provider_resource Current resource consumption or capacity.",
            "# TYPE owned_provider_resource gauge",
            "# HELP owned_provider_observer_collection_seconds Metrics collection duration.",
            "# TYPE owned_provider_observer_collection_seconds gauge",
            f"owned_provider_observer_collection_seconds {data['latency_ms'] / 1000}",
            "# HELP owned_provider_build_info Pinned upstream build identity.",
            "# TYPE owned_provider_build_info gauge",
            f'owned_provider_build_info{{upstream_commit="{UPSTREAM}"}} 1',
        ]
    )
    for resource, value in sorted(data["resources"].items()):
        lines.append(f'owned_provider_resource{{resource="{resource}"}} {value}')
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    server_version = "owned-provider-observer/1"

    def log_message(self, fmt, *args):
        print(
            json.dumps(
                {
                    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "service": "observer",
                    "level": "info",
                    "message": fmt % args,
                },
                sort_keys=True,
            ),
            flush=True,
        )

    def send(self, status: int, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/livez":
            self.send(200, "application/json", b'{"live":true}\n')
            return
        if self.path not in ("/readyz", "/metrics"):
            self.send(404, "application/json", b'{"error":"not found"}\n')
            return
        data = collect()
        if self.path == "/metrics":
            self.send(200, "text/plain; version=0.0.4", metrics(data).encode())
        else:
            body = (json.dumps(data, sort_keys=True) + "\n").encode()
            self.send(200 if data["ready"] else 503, "application/json", body)


if __name__ == "__main__":
    address = ("0.0.0.0", int(os.environ.get("OWNED_PROVIDER_OBSERVER_PORT", "9090")))
    ThreadingHTTPServer(address, Handler).serve_forever()
