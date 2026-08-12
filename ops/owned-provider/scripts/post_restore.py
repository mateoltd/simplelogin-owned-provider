"""Prove authenticated writes still work after either recovery path."""

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


BASE = os.environ["OWNED_PROVIDER_BASE_URL"].rstrip("/")


def request(method, path, body=None, api_key=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authentication"] = api_key
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def main():
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
    status, deleted = request(
        "DELETE", f"/api/aliases/{created['id']}", api_key=api_key
    )
    assert status == 200 and deleted["deleted"] is True
    print(
        json.dumps({"account_authentication": "ok", "post_restore_create_delete": "ok"})
    )


if __name__ == "__main__":
    main()
