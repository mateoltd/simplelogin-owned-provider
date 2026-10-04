"""Create and exercise a production-shaped alias population without a count cap."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time
import urllib.request
from pathlib import Path

import redis

from app.db import Session
from app.models import Alias, CustomDomain, User
from server import create_light_app


def api(base, method, path, body=None, api_key=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["Authentication"] = api_key
    request = urllib.request.Request(
        base + path, data=data, headers=headers, method=method
    )
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read(2_000_000))
        status = response.status
    return status, payload, (time.perf_counter() - started) * 1000


def seed(count: int) -> tuple[int, float]:
    user = User.get_by(email=os.environ["ADMIN_EMAIL"])
    domain = CustomDomain.get_by(domain=os.environ["OWNED_PROVIDER_E2E_DOMAIN"])
    prefix = "capacity-"
    Session.query(Alias).filter(Alias.email.like(f"{prefix}%@{domain.domain}")).delete(
        synchronize_session=False
    )
    Session.commit()
    existing = 0
    started = time.perf_counter()
    batch_size = 1000
    for start in range(existing, count, batch_size):
        rows = [
            {
                "user_id": user.id,
                "email": f"{prefix}{index:08d}@{domain.domain}",
                "name": "Capacity fixture",
                "enabled": True,
                "custom_domain_id": domain.id,
                "automatic_creation": False,
                "note": f"owned-provider capacity row {index:08d}",
                "mailbox_id": user.default_mailbox_id,
                "disable_pgp": False,
                "cannot_be_disabled": False,
                "disable_email_spoofing_check": False,
                "pinned": False,
            }
            for index in range(start, min(start + batch_size, count))
        ]
        if rows:
            Session.execute(Alias.__table__.insert(), rows)
            Session.commit()
    duration = time.perf_counter() - started
    total = (
        Session.query(Alias)
        .filter(Alias.email.like(f"{prefix}%@{domain.domain}"))
        .count()
    )
    return total, duration


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=10_000)
    parser.add_argument("--requests", type=int, default=20)
    args = parser.parse_args()
    if args.count < 10_000:
        raise RuntimeError(
            "the production capacity profile requires at least 10,000 aliases"
        )
    with create_light_app().app_context():
        total, seed_seconds = seed(args.count)
    base = os.environ["OWNED_PROVIDER_BASE_URL"].rstrip("/")
    redis_client = redis.Redis.from_url(os.environ["MEM_STORE_URI"])
    try:
        redis_client.flushdb()
    finally:
        redis_client.close()
    password = Path(os.environ["ADMIN_PASSWORD_FILE"]).read_text().strip()
    _, login, _ = api(
        base,
        "POST",
        "/api/auth/login",
        {
            "email": os.environ["ADMIN_EMAIL"],
            "password": password,
            "device": "capacity",
        },
    )
    api_key = login["api_key"]
    list_latencies = []
    for index in range(args.requests):
        status, payload, latency = api(
            base, "GET", f"/api/v2/aliases?page_id={index % 10}", api_key=api_key
        )
        assert status == 200 and payload["aliases"]
        list_latencies.append(latency)
    search_latencies = []
    for index in range(args.requests):
        target = (index * 251) % args.count
        status, payload, latency = api(
            base,
            "POST",
            "/api/v2/aliases?page_id=0",
            {"query": f"capacity-{target:08d}"},
            api_key,
        )
        assert status == 200 and any(
            item["email"].startswith(f"capacity-{target:08d}@")
            for item in payload["aliases"]
        )
        search_latencies.append(latency)
    result = {
        "aliases_requested": args.count,
        "capacity_aliases": total,
        "total_aliases": None,
        "seed_seconds": round(seed_seconds, 3),
        "seed_aliases_per_second": round(
            max(0, args.count) / max(seed_seconds, 0.001), 1
        ),
        "list_ms_p50": round(statistics.median(list_latencies), 3),
        "list_ms_p95": round(
            sorted(list_latencies)[int(len(list_latencies) * 0.95) - 1], 3
        ),
        "search_ms_p50": round(statistics.median(search_latencies), 3),
        "search_ms_p95": round(
            sorted(search_latencies)[int(len(search_latencies) * 0.95) - 1], 3
        ),
        "http_requests_per_operation": args.requests,
    }
    with create_light_app().app_context():
        result["total_aliases"] = Session.query(Alias).count()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
