"""Create and verify checkpoint markers in every locally owned state component."""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import time
import urllib.request
from email.message import EmailMessage
from pathlib import Path

import redis
from sqlalchemy import text

from app.db import Session
from server import create_light_app

UPLOAD_ROOT = Path("/code/static/upload")
UNSENT_ROOT = Path("/code/var/unsent")
MAILPIT = os.environ["OWNED_PROVIDER_MAILPIT_URL"].rstrip("/")


def message_exists(subject: str) -> bool:
    with urllib.request.urlopen(
        f"{MAILPIT}/api/v1/messages?limit=200", timeout=10
    ) as response:
        messages = json.loads(response.read(2_000_000)).get("messages", [])
    return any(item.get("Subject") == subject for item in messages)


def put(redis_client: redis.Redis, marker: str, phase: str):
    Session.execute(
        text("""
        INSERT INTO owned_provider.restore_marker(marker, phase)
        VALUES (:marker, :phase)
        ON CONFLICT (marker) DO UPDATE SET phase=excluded.phase, created_at=clock_timestamp()
        """),
        {"marker": marker, "phase": phase},
    )
    Session.commit()
    redis_client.set(f"owned-provider:restore:{marker}", phase)
    path = UPLOAD_ROOT / f"restore-{marker}.txt"
    path.write_text(f"{phase}\n")
    unsent_path = UNSENT_ROOT / f"restore-{marker}.txt"
    unsent_path.write_text(f"{phase}\n")
    message = EmailMessage()
    message["From"] = "restore-check@example.com"
    message["To"] = os.environ["ADMIN_EMAIL"]
    message["Subject"] = f"restore-{marker}"
    message.set_content(phase)
    with smtplib.SMTP("mailpit", 1025, timeout=10) as smtp:
        smtp.send_message(message)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not message_exists(message["Subject"]):
        time.sleep(0.2)
    if not message_exists(message["Subject"]):
        raise RuntimeError("Mailpit did not persist the restore marker")


def exists(redis_client: redis.Redis, marker: str) -> dict:
    database = bool(
        Session.execute(
            text("SELECT 1 FROM owned_provider.restore_marker WHERE marker=:marker"),
            {"marker": marker},
        ).scalar()
    )
    redis_value = redis_client.get(f"owned-provider:restore:{marker}")
    upload = UPLOAD_ROOT.joinpath(f"restore-{marker}.txt").is_file()
    unsent = UNSENT_ROOT.joinpath(f"restore-{marker}.txt").is_file()
    mail = message_exists(f"restore-{marker}")
    return {
        "postgres": database,
        "redis": redis_value is not None,
        "uploads": upload,
        "unsent_spool": unsent,
        "mail_store": mail,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("put", "verify"))
    parser.add_argument("marker")
    parser.add_argument("--phase", choices=("checkpoint", "after-checkpoint"))
    parser.add_argument("--expected", choices=("present", "absent"))
    args = parser.parse_args()
    redis_client = redis.Redis.from_url(os.environ["MEM_STORE_URI"])
    try:
        with create_light_app().app_context():
            if args.action == "put":
                if not args.phase:
                    parser.error("put requires --phase")
                put(redis_client, args.marker, args.phase)
                result = exists(redis_client, args.marker)
                if not all(result.values()):
                    raise RuntimeError(f"failed to create all markers: {result}")
            else:
                if not args.expected:
                    parser.error("verify requires --expected")
                result = exists(redis_client, args.marker)
                expected = args.expected == "present"
                if any(value != expected for value in result.values()):
                    raise RuntimeError(
                        f"restore marker {args.marker} expected {args.expected}: {result}"
                    )
            result.update({"marker": args.marker, "action": args.action})
            print(json.dumps(result, sort_keys=True))
    finally:
        redis_client.close()


if __name__ == "__main__":
    main()
