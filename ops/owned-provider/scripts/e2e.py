"""Exercise the deployed HTTP, SMTP, queue, concurrency, and rate-limit paths."""

from __future__ import annotations

import concurrent.futures
import html
import json
import os
import re
import smtplib
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from http.cookiejar import CookieJar
from pathlib import Path

import redis

from app.db import Session
from app.jobs.export_user_data_job import ExportUserDataJob
from app.models import Job, JobState, User
from server import create_light_app


BASE_URL = os.environ["OWNED_PROVIDER_BASE_URL"].rstrip("/")
MAILPIT_URL = os.environ["OWNED_PROVIDER_MAILPIT_URL"].rstrip("/")
SMTP_HOST = os.environ["OWNED_PROVIDER_SMTP_HOST"]
SMTP_PORT = int(os.environ["OWNED_PROVIDER_SMTP_PORT"])
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
CUSTOM_DOMAIN = os.environ["OWNED_PROVIDER_CUSTOM_DOMAIN"]
MAILBOX_DOMAIN = os.environ["OWNED_PROVIDER_E2E_MAILBOX_DOMAIN"]
PASSWORD = Path(os.environ["ADMIN_PASSWORD_FILE"]).read_text().strip()
MAX_BODY = 2_000_000

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))


def http_request(
    method: str, path: str, body=None, api_key=None, expected=(200,), client=opener
):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["Authentication"] = api_key
    request = urllib.request.Request(
        BASE_URL + path, data=data, headers=headers, method=method
    )
    try:
        response = client.open(request, timeout=30)
        status = response.status
        encoded = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        encoded = error.read(MAX_BODY + 1)
    if len(encoded) > MAX_BODY:
        raise AssertionError(f"response from {path} exceeded {MAX_BODY} bytes")
    decoded = encoded.decode(errors="replace")
    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError:
        payload = decoded
    if status not in expected:
        raise AssertionError(
            f"{method} {path}: expected {expected}, got {status}: {payload}"
        )
    return status, payload


def mailpit_request(path: str):
    with urllib.request.urlopen(MAILPIT_URL + path, timeout=10) as response:
        encoded = response.read(MAX_BODY + 1)
    if len(encoded) > MAX_BODY:
        raise AssertionError("Mailpit response exceeded safety limit")
    return json.loads(encoded)


def mailpit_messages():
    return mailpit_request("/api/v1/messages?limit=200").get("messages", [])


def message_detail(message_id: str):
    return mailpit_request(f"/api/v1/message/{urllib.parse.quote(message_id)}")


def wait_for_message(subject: str, recipient: str, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for message in mailpit_messages():
            if message.get("Subject") != subject:
                continue
            if recipient.lower() not in json.dumps(message).lower():
                continue
            return message_detail(str(message["ID"]))
        time.sleep(0.5)
    raise AssertionError(f"Mailpit did not receive {subject!r} for {recipient!r}")


def wait_for_mailbox_verification(mailbox_email: str):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        for message in mailpit_messages():
            if mailbox_email.lower() not in json.dumps(message).lower():
                continue
            detail = message_detail(str(message["ID"]))
            content = html.unescape(json.dumps(detail))
            match = re.search(
                r"mailbox_id=(\d+)(?:&|\\u0026|&amp;)code=([A-Za-z0-9._~-]+)", content
            )
            if match:
                mailbox_id, code = match.groups()
                path = "/dashboard/mailbox_verify?" + urllib.parse.urlencode(
                    {"mailbox_id": mailbox_id, "code": code}
                )
                status, _ = http_request("GET", path, expected=(200, 302))
                return int(mailbox_id), status
        time.sleep(0.5)
    raise AssertionError(f"mailbox verification message not found for {mailbox_email}")


def wait_for_mailbox_deletion(mailbox_id: int, api_key: str):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        _, payload = http_request("GET", "/api/v2/mailboxes", api_key=api_key)
        if not any(item["id"] == mailbox_id for item in payload["mailboxes"]):
            return
        time.sleep(0.5)
    raise AssertionError(f"mailbox {mailbox_id} was not deleted by the job runner")


def send_mail(sender: str, recipient: str, subject: str):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(f"owned provider real SMTP lifecycle: {subject}")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        smtp.send_message(message, from_addr=sender, to_addrs=[recipient])


def authenticate():
    _, login = http_request(
        "POST",
        "/api/auth/login",
        {"email": ADMIN_EMAIL, "password": PASSWORD, "device": "owned-provider-e2e"},
    )
    api_key = login.get("api_key")
    if not api_key or len(api_key) < 8:
        raise AssertionError("account login did not issue an API key")
    http_request(
        "GET",
        "/api/user_info",
        api_key="invalid",
        expected=(401,),
        client=urllib.request.build_opener(),
    )
    _, user_info = http_request("GET", "/api/user_info", api_key=api_key)
    assert user_info["email"] == ADMIN_EMAIL
    return api_key


def queue_probe():
    with create_light_app().app_context():
        user = User.get_by(email=ADMIN_EMAIL)
        job = ExportUserDataJob(user).store_job_in_db()
        if job is None:
            job = (
                Job.filter(Job.payload.op("->>")("user_id") == str(user.id))
                .order_by(Job.id.desc())
                .first()
            )
        job_id = job.id

    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        with create_light_app().app_context():
            Session.expire_all()
            state = Job.get(job_id).state
        if state == JobState.done.value:
            wait_for_message("Your SimpleLogin data", ADMIN_EMAIL)
            return job_id
        if state == JobState.error.value:
            raise AssertionError(f"queue job {job_id} entered error state")
        time.sleep(1)
    raise AssertionError(f"queue job {job_id} was not processed")


def main():
    nonce = str(time.time_ns())
    api_key = authenticate()

    # The API performs a real MX lookup before sending. Use a domain with valid
    # MX records; POSTFIX_SERVER still terminates delivery at local Mailpit.
    secondary = f"owned-provider-{nonce}@{MAILBOX_DOMAIN}"
    _, mailbox = http_request(
        "POST", "/api/mailboxes", {"email": secondary}, api_key, expected=(201,)
    )
    assert mailbox["verified"] is False
    mailbox_id, _ = wait_for_mailbox_verification(secondary)
    assert mailbox_id == mailbox["id"]
    _, mailboxes = http_request("GET", "/api/v2/mailboxes", api_key=api_key)
    verified = {item["id"]: item for item in mailboxes["mailboxes"]}
    assert verified[mailbox_id]["verified"] is True
    default_mailbox = next(item for item in mailboxes["mailboxes"] if item["default"])

    _, domains = http_request("GET", "/api/custom_domains", api_key=api_key)
    custom_domain = next(
        domain
        for domain in domains["custom_domains"]
        if domain["domain_name"] == CUSTOM_DOMAIN
    )
    _, updated_domain = http_request(
        "PATCH",
        f"/api/custom_domains/{custom_domain['id']}",
        {
            "name": "Owned local domain",
            "catch_all": True,
            "random_prefix_generation": True,
            "mailbox_ids": [default_mailbox["id"], mailbox_id],
        },
        api_key,
    )
    assert updated_domain["custom_domain"]["catch_all"] is True

    _, options = http_request("GET", "/api/v5/alias/options", api_key=api_key)
    domain_option = next(
        suffix
        for suffix in options["suffixes"]
        if suffix["suffix"] == f"@{CUSTOM_DOMAIN}"
    )
    custom_prefix = f"recovery-{nonce}"
    _, custom_alias = http_request(
        "POST",
        "/api/v3/alias/custom/new?hostname=recovery.example",
        {
            "alias_prefix": custom_prefix,
            "signed_suffix": domain_option["signed_suffix"],
            "mailbox_ids": [default_mailbox["id"], mailbox_id],
            "name": "Recovery fixture",
            "note": "relationship recovery fixture",
        },
        api_key,
        expected=(201,),
    )
    assert custom_alias["alias"] == f"{custom_prefix}@{CUSTOM_DOMAIN}"

    _, random_alias = http_request(
        "POST",
        "/api/alias/random/new?mode=uuid",
        {"note": "random lifecycle fixture"},
        api_key,
        expected=(201,),
    )
    random_id = random_alias["id"]

    _, alias_list = http_request("GET", "/api/v2/aliases?page_id=0", api_key=api_key)
    listed_ids = {item["id"] for item in alias_list["aliases"]}
    assert custom_alias["id"] in listed_ids and random_id in listed_ids

    _, search = http_request(
        "POST", "/api/v2/aliases?page_id=0", {"query": custom_prefix}, api_key
    )
    assert any(item["id"] == custom_alias["id"] for item in search["aliases"])
    http_request(
        "PUT",
        f"/api/aliases/{custom_alias['id']}",
        {
            "name": "Updated recovery fixture",
            "note": "updated and searchable",
            "pinned": True,
            "mailbox_ids": [default_mailbox["id"], mailbox_id],
        },
        api_key,
    )
    _, alias_detail = http_request(
        "GET", f"/api/aliases/{custom_alias['id']}", api_key=api_key
    )
    assert alias_detail["note"] == "updated and searchable"
    assert alias_detail["pinned"] is True

    _, toggled = http_request(
        "POST", f"/api/aliases/{custom_alias['id']}/toggle", api_key=api_key
    )
    assert toggled["enabled"] is False
    _, toggled = http_request(
        "POST", f"/api/aliases/{custom_alias['id']}/toggle", api_key=api_key
    )
    assert toggled["enabled"] is True

    contact_address = f"contact-{nonce}@example.com"
    _, contact = http_request(
        "POST",
        f"/api/aliases/{custom_alias['id']}/contacts",
        {"contact": contact_address},
        api_key,
        expected=(201,),
    )
    reverse_alias = contact["reverse_alias_address"]
    _, contacts = http_request(
        "GET", f"/api/aliases/{custom_alias['id']}/contacts?page_id=0", api_key=api_key
    )
    assert any(item["id"] == contact["id"] for item in contacts["contacts"])
    _, contact_toggle = http_request(
        "POST", f"/api/contacts/{contact['id']}/toggle", api_key=api_key
    )
    assert contact_toggle["block_forward"] is True
    http_request("POST", f"/api/contacts/{contact['id']}/toggle", api_key=api_key)

    forward_subject = f"owned-forward-{nonce}"
    send_mail(contact_address, custom_alias["alias"], forward_subject)
    wait_for_message(forward_subject, ADMIN_EMAIL)
    wait_for_message(forward_subject, secondary)

    reply_subject = f"owned-reply-{nonce}"
    send_mail(ADMIN_EMAIL, reverse_alias, reply_subject)
    wait_for_message(reply_subject, contact_address)

    _, stats = http_request("GET", "/api/stats", api_key=api_key)
    assert stats["nb_forward"] >= 1 and stats["nb_reply"] >= 1
    _, upstream_export = http_request("GET", "/api/export/data", api_key=api_key)
    assert custom_alias["alias"] in {
        item["email"] for item in upstream_export["aliases"]
    }
    _, csv_export = http_request("GET", "/api/export/aliases", api_key=api_key)
    assert custom_alias["alias"] in csv_export

    http_request("DELETE", f"/api/aliases/{random_id}", api_key=api_key)
    _, deleted_search = http_request(
        "POST", "/api/v2/aliases?page_id=0", {"query": random_alias["alias"]}, api_key
    )
    assert not deleted_search["aliases"]

    http_request(
        "DELETE",
        f"/api/mailboxes/{mailbox_id}",
        {"transfer_aliases_to": default_mailbox["id"]},
        api_key,
    )
    wait_for_mailbox_deletion(mailbox_id, api_key)
    _, alias_after_transfer = http_request(
        "GET", f"/api/aliases/{custom_alias['id']}", api_key=api_key
    )
    assert [item["id"] for item in alias_after_transfer["mailboxes"]] == [
        default_mailbox["id"]
    ]

    queue_job_id = queue_probe()

    redis.Redis.from_url(os.environ["MEM_STORE_URI"]).flushdb()

    def create_concurrent(index: int):
        return http_request(
            "POST",
            "/api/alias/random/new?mode=uuid",
            {"note": f"concurrency fixture {index}"},
            api_key,
            expected=(201, 429),
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        concurrent_results = list(pool.map(create_concurrent, range(8)))
    accepted = [payload for status, payload in concurrent_results if status == 201]
    lock_rejected = [payload for status, payload in concurrent_results if status == 429]
    assert accepted and lock_rejected
    assert all(payload == {"error": "Rate limit exceeded"} for payload in lock_rejected)
    concurrent_addresses = [payload["alias"] for payload in accepted]
    assert len(set(concurrent_addresses)) == len(concurrent_addresses)

    # Test the configured request quota independently from the parallel
    # creation lock so lock rejections do not consume the quota under test.
    redis.Redis.from_url(os.environ["MEM_STORE_URI"]).flushdb()

    sequential_success = 0
    sequential_created = []
    rate_limited = None
    for index in range(25):
        status, payload = create_concurrent(100 + index)
        if status == 429:
            rate_limited = payload
            break
        sequential_success += 1
        sequential_created.append(payload)
    assert sequential_success == 20
    assert rate_limited == {"error": "Rate limit exceeded"}
    redis.Redis.from_url(os.environ["MEM_STORE_URI"]).flushdb()

    for alias_id in [
        custom_alias["id"],
        *(item["id"] for item in accepted),
        *(item["id"] for item in sequential_created),
    ]:
        http_request("DELETE", f"/api/aliases/{alias_id}", api_key=api_key)

    print(
        json.dumps(
            {
                "account_authentication": "ok",
                "api_authentication": "ok",
                "custom_alias": custom_alias["alias"],
                "custom_domain": CUSTOM_DOMAIN,
                "mailbox_verified_via_sink": secondary,
                "reverse_alias": reverse_alias,
                "inbound_forwarding": "ok",
                "outbound_reverse_alias": "ok",
                "queue_job_id": queue_job_id,
                "concurrent_accepted": len(accepted),
                "concurrent_lock_rejected": len(lock_rejected),
                "rate_limit_successes_before_429": 20,
                "list_search_update_toggle_delete": "ok",
                "mailbox_create_verify_transfer_delete": "ok",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
