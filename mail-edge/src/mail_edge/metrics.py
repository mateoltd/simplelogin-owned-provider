"""Private bounded-cardinality health and Prometheus metrics service."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .db import migration_status
from .runtime import Runtime, build_runtime


def render_metrics(runtime: Runtime) -> str:
    counts = runtime.repository.state_counts()
    lines = [
        "# HELP mail_edge_messages Durable messages by direction and state.",
        "# TYPE mail_edge_messages gauge",
    ]
    for direction in sorted(counts):
        for state in sorted(counts[direction]):
            lines.append(
                f'mail_edge_messages{{direction="{direction}",state="{state}"}} '
                f"{counts[direction][state]}"
            )
    unknown = counts["outbound"].get("unknown", 0)
    quarantine = runtime.repository.quarantine_count()
    lines.extend(
        [
            "# HELP mail_edge_unknown_submissions "
            "Submissions requiring reconciliation.",
            "# TYPE mail_edge_unknown_submissions gauge",
            f"mail_edge_unknown_submissions {unknown}",
            "# HELP mail_edge_open_quarantine Open quarantine records.",
            "# TYPE mail_edge_open_quarantine gauge",
            f"mail_edge_open_quarantine {quarantine}",
        ]
    )
    return "\n".join(lines) + "\n"


def readiness(runtime: Runtime) -> tuple[bool, dict[str, object]]:
    expected, applied = migration_status(runtime.database)
    database_ok = runtime.database.ping()
    migrations_ok = expected == applied
    blob_ok = runtime.blobs.root.is_dir() and os.access(runtime.blobs.root, os.W_OK)
    return (
        database_ok and migrations_ok and blob_ok,
        {
            "database": database_ok,
            "migrations": migrations_ok,
            "blob_store": blob_ok,
        },
    )


class MetricsHandler(BaseHTTPRequestHandler):
    runtime: Runtime
    server_version = "mail-edge"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/livez":
            self._respond(200, b'{"live":true}\n', "application/json")
        elif self.path == "/readyz":
            ready, checks = readiness(self.runtime)
            body = (
                json.dumps(
                    {"ready": ready, "checks": checks},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )
            self._respond(200 if ready else 503, body, "application/json")
        elif self.path == "/metrics":
            self._respond(
                200,
                render_metrics(self.runtime).encode(),
                "text/plain; version=0.0.4",
            )
        else:
            self._respond(404, b'{"error":"not_found"}\n', "application/json")

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    runtime = build_runtime()
    handler = type("ConfiguredMetricsHandler", (MetricsHandler,), {"runtime": runtime})
    server = ThreadingHTTPServer(
        (
            os.environ.get("MAIL_EDGE_METRICS_HOST", "127.0.0.1"),
            int(os.environ.get("MAIL_EDGE_METRICS_PORT", "9090")),
        ),
        handler,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
