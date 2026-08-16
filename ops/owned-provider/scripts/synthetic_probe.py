"""Run a real authenticated API lifecycle and SMTP handshake, then record it."""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import time
import urllib.error
import urllib.request
from pathlib import Path
from sqlalchemy import text

from app.db import Session
from server import create_light_app

BASE = os.environ.get("OWNED_PROVIDER_BASE_URL", "http://app:7777").rstrip("/")
PASSWORD = Path(os.environ["ADMIN_PASSWORD_FILE"]).read_text().strip()


def api(method, path, body=None, api_key=None, expected=(200,)):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["Authentication"] = api_key
    request = urllib.request.Request(
        BASE + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status, payload = response.status, json.loads(response.read(1_000_000))
    except urllib.error.HTTPError as error:
        status, payload = error.code, json.loads(error.read(1_000_000))
    if status not in expected:
        raise RuntimeError(f"{method} {path} returned {status}: {payload}")
    return payload


def record(success: bool, latency_ms: float, detail: dict):
    with create_light_app().app_context():
        Session.execute(
            text("""
            INSERT INTO owned_provider.probe_result(probe_name, success, latency_ms, detail)
            VALUES ('api-smtp', :success, :latency_ms, CAST(:detail AS jsonb))
            """),
            {
                "success": success,
                "latency_ms": latency_ms,
                "detail": json.dumps(detail, sort_keys=True),
            },
        )
        Session.execute(text("""
            DELETE FROM owned_provider.probe_result
            WHERE checked_at < clock_timestamp() - interval '30 days'
            """))
        Session.commit()


def run_once() -> dict:
    started = time.monotonic()
    alias_id = None
    result = {"api": False, "smtp": False, "lifecycle": False}
    try:
        login = api(
            "POST",
            "/api/auth/login",
            {
                "email": os.environ["ADMIN_EMAIL"],
                "password": PASSWORD,
                "device": "owned-provider-synthetic",
            },
        )
        api_key = login["api_key"]
        created = api(
            "POST",
            "/api/alias/random/new?mode=uuid",
            {"note": "owned-provider-synthetic"},
            api_key,
            expected=(201,),
        )
        alias_id = created["id"]
        result["api"] = True
        if api("POST", f"/api/aliases/{alias_id}/toggle", api_key=api_key)["enabled"]:
            raise RuntimeError("first alias toggle did not disable")
        if not api("POST", f"/api/aliases/{alias_id}/toggle", api_key=api_key)[
            "enabled"
        ]:
            raise RuntimeError("second alias toggle did not enable")
        api("DELETE", f"/api/aliases/{alias_id}", api_key=api_key)
        alias_id = None
        result["lifecycle"] = True
        with smtplib.SMTP(
            os.environ.get("OWNED_PROVIDER_SMTP_HOST", "email"),
            int(os.environ.get("OWNED_PROVIDER_SMTP_PORT", "20381")),
            timeout=10,
        ) as smtp:
            code, _ = smtp.ehlo()
            if code != 250:
                raise RuntimeError(f"SMTP EHLO returned {code}")
        result["smtp"] = True
        relay_host = os.environ["POSTFIX_SERVER"].split(",", 1)[0].strip()
        with smtplib.SMTP(
            relay_host, int(os.environ["POSTFIX_PORT"]), timeout=10
        ) as relay:
            code, _ = relay.ehlo()
            if code != 250:
                raise RuntimeError(f"outbound relay EHLO returned {code}")
        result["outbound_relay"] = True
        result["success"] = True
    except Exception as error:
        result["success"] = False
        result["error"] = f"{type(error).__name__}: {error}"[:300]
        if alias_id is not None:
            try:
                api("DELETE", f"/api/aliases/{alias_id}", api_key=api_key)
            except Exception:
                pass
    result["latency_ms"] = round((time.monotonic() - started) * 1000, 3)
    record(result["success"], result["latency_ms"], result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--loop-seconds", type=int, default=0)
    args = parser.parse_args()
    while True:
        result = run_once()
        print(json.dumps(result, sort_keys=True), flush=True)
        if not args.loop_seconds:
            return 0 if result["success"] else 1
        time.sleep(max(60, args.loop_seconds))


if __name__ == "__main__":
    raise SystemExit(main())
