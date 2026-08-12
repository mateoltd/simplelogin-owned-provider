"""Run the laboratory's real Bitwarden generator test without changing its worktree."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def api(base, method, path, body=None, api_key=None, expected=(200,)):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authentication"] = api_key
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            status, encoded = response.status, response.read(1_000_001)
    except urllib.error.HTTPError as error:
        status, encoded = error.code, error.read(1_000_001)
    if len(encoded) > 1_000_000:
        raise RuntimeError("SimpleLogin response exceeded 1 MiB")
    payload = json.loads(encoded)
    if status not in expected:
        raise RuntimeError(f"{method} {path} returned {status}: {payload}")
    return payload


def git(worktree: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(worktree), *args], text=True
    ).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sdk_worktree", type=Path)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    worktree = args.sdk_worktree.resolve()
    if not (worktree / "support/simplelogin/SIMPLELOGIN_COMMIT").is_file():
        raise RuntimeError(
            "SDK worktree does not contain the real SimpleLogin laboratory"
        )
    lab_pin = (worktree / "support/simplelogin/SIMPLELOGIN_COMMIT").read_text().strip()
    expected_pin = (
        Path(__file__)
        .resolve()
        .parents[1]
        .joinpath("UPSTREAM_COMMIT")
        .read_text()
        .strip()
    )
    if lab_pin != expected_pin:
        raise RuntimeError(
            f"SDK lab pin {lab_pin} differs from provider pin {expected_pin}"
        )
    before_head = git(worktree, "rev-parse", "HEAD")
    before_status = git(worktree, "status", "--porcelain=v1")
    if before_status:
        raise RuntimeError("SDK conformance requires a clean SDK worktree")

    base = args.base_url.rstrip("/")
    password = args.password_file.read_text().strip()
    login = api(
        base,
        "POST",
        "/api/auth/login",
        {"email": args.email, "password": password, "device": "sdk-conformance"},
    )
    api_key = login["api_key"]
    nonce = str(time.time_ns())
    website = f"sdk-conformance-{nonce}.com"
    domains = api(base, "GET", "/api/custom_domains", api_key=api_key)["custom_domains"]
    if not domains:
        raise RuntimeError("SDK conformance requires a verified custom domain")
    custom_domain = domains[0]

    # A random-prefix custom domain produces a fresh suffix on every call, so
    # the options response cannot predict the subsequent one-click endpoint.
    # Temporarily disable that preference to give the unchanged SDK live test
    # a deterministic expected address, then restore it in the cleanup path.
    api(
        base,
        "PATCH",
        f"/api/custom_domains/{custom_domain['id']}",
        {"random_prefix_generation": False},
        api_key,
    )
    try:
        options = api(
            base, "GET", f"/api/v5/alias/options?hostname={website}", api_key=api_key
        )
        suffix = options["suffixes"][0]["suffix"]
        if not suffix.startswith("@"):
            raise RuntimeError(
                f"deterministic custom-domain suffix not first: {suffix}"
            )
        expected_alias = options["prefix_suggestion"] + suffix

        environment = os.environ.copy()
        environment.update(
            {
                "SIMPLELOGIN_REAL_BASE_URL": base,
                "SIMPLELOGIN_REAL_API_KEY": api_key,
                "SIMPLELOGIN_REAL_WEBSITE": website,
                "SIMPLELOGIN_REAL_EXPECTED_ALIAS": expected_alias,
                "CARGO_TARGET_DIR": str(args.target_dir.resolve()),
            }
        )
        command = [
            "cargo",
            "test",
            "--locked",
            "-p",
            "bitwarden-generators",
            "username_forwarders::simplelogin::tests::test_real_simplelogin_service",
            "--",
            "--ignored",
            "--exact",
        ]
        subprocess.run(command, cwd=worktree, env=environment, check=True)
    finally:
        aliases = api(
            base,
            "POST",
            "/api/v2/aliases?page_id=0",
            {"query": "sdk-conformance-"},
            api_key,
        )
        for created in aliases["aliases"]:
            api(base, "DELETE", f"/api/aliases/{created['id']}", api_key=api_key)
        api(
            base,
            "PATCH",
            f"/api/custom_domains/{custom_domain['id']}",
            {"random_prefix_generation": custom_domain["random_prefix_generation"]},
            api_key,
        )
        after_head = git(worktree, "rev-parse", "HEAD")
        after_status = git(worktree, "status", "--porcelain=v1")
        if after_head != before_head or after_status != before_status:
            raise RuntimeError("SDK conformance changed the SDK worktree")
    print(
        json.dumps(
            {
                "sdk_head": before_head,
                "sdk_worktree_clean": True,
                "provider_pin": expected_pin,
                "expected_alias": expected_alias,
                "real_generator_test": "passed",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
