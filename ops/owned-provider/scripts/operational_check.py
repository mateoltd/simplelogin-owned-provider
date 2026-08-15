"""Emit dependency, migration, queue, and mail-state health as JSON."""

import json
import os
import urllib.request
import urllib.error

import redis
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.db import Session
from app.models import Alias, Contact, EmailLog, Job, JobState, Mailbox, User
from server import create_light_app


def main():
    base_url = os.environ.get("OWNED_PROVIDER_BASE_URL", "http://app:7777")
    with urllib.request.urlopen(
        base_url.rstrip("/") + "/health", timeout=5
    ) as response:
        http_ok = response.status == 200 and response.read() == b"success"
    mail_edge_ok = None
    if os.environ.get("MAIL_EDGE_CONFIG_PATH"):
        try:
            with urllib.request.urlopen(
                base_url.rstrip("/") + "/health/mail-edge/readyz", timeout=5
            ) as response:
                mail_edge_ok = response.status == 200
                response.read(1_048_577)
        except (OSError, urllib.error.HTTPError):
            mail_edge_ok = False
    redis_client = redis.Redis.from_url(os.environ["MEM_STORE_URI"])
    try:
        redis_ok = bool(redis_client.ping())
    finally:
        redis_client.close()
    with create_light_app().app_context():
        db_ok = Session.execute("SELECT 1").scalar() == 1
        current = Session.execute("SELECT version_num FROM alembic_version").scalar()
        expected = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
        result = {
            "http": http_ok,
            "mail_edge": mail_edge_ok,
            "postgres": db_ok,
            "redis": redis_ok,
            "migration_current": current,
            "migration_expected": expected,
            "migration_at_head": current == expected,
            "users": Session.query(User).count(),
            "mailboxes": Session.query(Mailbox).count(),
            "aliases": Session.query(Alias).count(),
            "contacts": Session.query(Contact).count(),
            "email_logs": Session.query(EmailLog).count(),
            "mail_edge_replay_nonces": Session.execute(
                "SELECT count(*) FROM mail_edge_replay_nonce"
            ).scalar(),
            "mail_edge_callback_receipts": Session.execute(
                "SELECT count(*) FROM mail_edge_callback_receipt"
            ).scalar(),
            "mail_edge_outbound_projections": Session.execute(
                "SELECT count(*) FROM mail_edge_outbound_projection"
            ).scalar(),
            "mail_edge_binding_projections": Session.execute(
                "SELECT count(*) FROM mail_edge_route_binding_projection"
            ).scalar(),
            "jobs_ready": Session.query(Job)
            .filter(Job.state == JobState.ready.value)
            .count(),
            "jobs_taken": Session.query(Job)
            .filter(Job.state == JobState.taken.value)
            .count(),
            "jobs_error": Session.query(Job)
            .filter(Job.state == JobState.error.value)
            .count(),
        }
    if not all(
        (
            http_ok,
            redis_ok,
            db_ok,
            result["migration_at_head"],
            mail_edge_ok is not False,
        )
    ):
        raise SystemExit(json.dumps(result, sort_keys=True))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
