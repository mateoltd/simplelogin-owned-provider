"""Prove authenticated API writes and both mail directions after recovery."""

from __future__ import annotations

import json
import os
import smtplib
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path

from app.db import Session
from app.models import MailEdgeOutboundProjection
from server import create_light_app


BASE = os.environ["OWNED_PROVIDER_BASE_URL"].rstrip("/")
MAILPIT = os.environ["OWNED_PROVIDER_MAILPIT_URL"].rstrip("/")


def request(method, path, body=None, api_key=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authentication"] = api_key
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.loads(response.read(2_000_000))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read(2_000_000))


def messages():
    with urllib.request.urlopen(
        f"{MAILPIT}/api/v1/messages?limit=200", timeout=10
    ) as response:
        return json.loads(response.read(2_000_000)).get("messages", [])


def wait_for(subject: str, recipient: str):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        for item in messages():
            if (
                item.get("Subject") == subject
                and recipient.lower() in json.dumps(item).lower()
            ):
                return
        time.sleep(0.5)
    raise RuntimeError(f"mail not observed after restore: {subject}")


def send(sender: str, recipient: str, subject: str):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content("owned-provider post-restore traffic proof")
    with smtplib.SMTP(
        os.environ["OWNED_PROVIDER_SMTP_HOST"],
        int(os.environ["OWNED_PROVIDER_SMTP_PORT"]),
        timeout=10,
    ) as smtp:
        smtp.send_message(message, from_addr=sender, to_addrs=[recipient])


def main():
    mail_edge_enabled = bool(os.environ.get("MAIL_EDGE_CONFIG_PATH"))
    with create_light_app().app_context():
        outbound_before = Session.query(MailEdgeOutboundProjection).count()
    password = Path(os.environ["ADMIN_PASSWORD_FILE"]).read_text().strip()
    status, login = request(
        "POST",
        "/api/auth/login",
        {
            "email": os.environ["ADMIN_EMAIL"],
            "password": password,
            "device": "post-restore",
        },
    )
    assert status == 200
    api_key = login["api_key"]
    status, created = request(
        "POST",
        "/api/alias/random/new?mode=uuid",
        {"note": f"post-restore-{time.time_ns()}"},
        api_key,
    )
    assert status == 201
    contact_address = f"post-restore-{time.time_ns()}@example.com"
    status, contact = request(
        "POST",
        f"/api/aliases/{created['id']}/contacts",
        {"contact": contact_address},
        api_key,
    )
    assert status == 201
    inbound_subject = f"restore-inbound-{time.time_ns()}"
    send(contact_address, created["alias"], inbound_subject)
    wait_for(inbound_subject, os.environ["ADMIN_EMAIL"])
    reply_subject = f"restore-reply-{time.time_ns()}"
    send(os.environ["ADMIN_EMAIL"], contact["reverse_alias_address"], reply_subject)
    wait_for(reply_subject, contact_address)
    with create_light_app().app_context():
        outbound_after = Session.query(MailEdgeOutboundProjection).count()
    if mail_edge_enabled and outbound_after < outbound_before + 2:
        raise RuntimeError(
            "post-restore Mail Edge outbound projections were not committed"
        )
    status, deleted = request(
        "DELETE", f"/api/aliases/{created['id']}", api_key=api_key
    )
    assert status == 200 and deleted["deleted"] is True
    print(
        json.dumps(
            {
                "account_authentication": "ok",
                "post_restore_create_delete": "ok",
                "post_restore_inbound": "ok",
                "post_restore_reverse_reply": "ok",
                "post_restore_mail_edge_outbound": (
                    "ok" if mail_edge_enabled else "disabled"
                ),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
