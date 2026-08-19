"""Audit local containment, secret exposure, container hardening, and provenance."""

import argparse
import json
import stat
import subprocess
from pathlib import Path

from log_wrapper import sensitive_kinds


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--project", required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()
    runtime = args.runtime.resolve()

    expected_upstream = (
        (repository / "ops/owned-provider/UPSTREAM_COMMIT").read_text().strip()
    )
    expected_revision = command("git", "-C", str(repository), "rev-parse", "HEAD")
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            expected_upstream,
            "HEAD",
        ],
        check=True,
    )
    changed = command(
        "git", "-C", str(repository), "diff", "--name-only", expected_upstream, "--"
    ).splitlines()
    exact_host_paths = {
        ".python-version",
        ".gitignore",
        ".dockerignore",
        "Dockerfile",
        "app/admin/base.py",
        "app/admin/custom_domain_search.py",
        "app/admin/email_search.py",
        "app/admin/index.py",
        "app/api/base.py",
        "app/api/serializer.py",
        "app/api/views/auth.py",
        "app/api/views/mailbox.py",
        "app/auth/views/fido.py",
        "app/dashboard/views/alias_contact_manager.py",
        "app/dashboard/views/enter_admin.py",
        "app/dashboard/views/fido_setup.py",
        "app/dashboard/views/mailbox.py",
        "app/db.py",
        "app/email_utils.py",
        "app/events/event_dispatcher.py",
        "app/jose_utils.py",
        "app/mail_sender.py",
        "app/mailbox_utils.py",
        "app/models.py",
        "app/oauth/views/authorize.py",
        "app/onboarding/utils.py",
        "app/pgp_utils.py",
        "app/session.py",
        "app/webauthn_utils.py",
        "commands/check_user_leaks.py",
        "commands/handle_leaks.py",
        "cron.py",
        "docs/mail-edge-bridge.md",
        "email_handler.py",
        "job_runner.py",
        "migrations/versions/2021_080409_9014cca7097c_.py",
        "monitoring.py",
        "oauth_tester.py",
        "simplelogin_app.py",
        "pyproject.toml",
        "static/assets/js/vendors/webauthn.js",
        "static/js/index.js",
        "static/package-lock.json",
        "static/package.json",
        "templates/admin/custom_domain_search.html",
        "templates/admin/abuser_lookup.html",
        "templates/admin/email_search.html",
        "templates/admin/mailbox_domain_search.html",
        "templates/base.html",
        "templates/dashboard/subdomain.html",
        "templates/dashboard/support.html",
        "templates/footer.html",
        "templates/phone/phone_reservation.html",
        "templates/header.html",
        "tests/admin/test_custom_domain_search.py",
        "tests/admin/test_email_search.py",
        "tests/api/test_auth_mfa.py",
        "tests/auth/test_oidc.py",
        "tests/conftest.py",
        "tests/test_email_utils.py",
        "tests/handler/test_encrypt_pgp.py",
        "tests/http_socket_fixture.py",
        "tests/test_extensions.py",
        "tests/test_http_socket_security.py",
        "tests/test_owned_provider_logging.py",
        "tests/test_onboarding.py",
        "tests/test_pgp_utils.py",
        "tests/test_server.py",
        "tests/test_smtp_socket_security.py",
        "tests/test_webauthn_utils.py",
        "tests/utils.py",
        "uv.lock",
    }
    allowed_prefixes = (
        "app/mail_edge/",
        "migrations/versions/2026_0814",
        "ops/owned-provider/",
        "tests/mail_edge/",
        "tests/mail_edge_integration/",
    )
    unexpected = [
        path
        for path in changed
        if path not in exact_host_paths
        and not any(path.startswith(prefix) for prefix in allowed_prefixes)
    ]
    if unexpected:
        raise RuntimeError(f"local changes escaped the operations layer: {unexpected}")

    secrets = {}
    for path in sorted((runtime / "secrets").iterdir()):
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode != 0o600:
            raise RuntimeError(
                f"secret {path.name} has mode {oct(mode)}, expected 0o600"
            )
        secrets[path.name] = path.read_text().strip()

    container_ids = command(
        "docker",
        "ps",
        "--filter",
        f"label=com.docker.compose.project={args.project}",
        "--format",
        "{{.ID}}",
    ).splitlines()
    if not container_ids:
        raise RuntimeError("no running deployment containers")
    inspected = json.loads(command("docker", "inspect", *container_ids))
    encoded_inspect = json.dumps(inspected)
    leaked = [
        name for name, value in secrets.items() if value and value in encoded_inspect
    ]
    if leaked:
        raise RuntimeError(f"secret values leaked into Docker metadata: {leaked}")

    hardened = {}
    mail_edge_mounts = {}
    secret_volume_mounts = {}
    secret_file_access = {}
    writable_volume_paths = {}
    loopback_ports = True
    for container in inspected:
        service = container["Config"]["Labels"].get("com.docker.compose.service")
        bindings = container["HostConfig"].get("PortBindings") or {}
        for values in bindings.values():
            for binding in values or []:
                if binding.get("HostIp") not in ("127.0.0.1", "::1"):
                    loopback_ports = False
        if service in {"app", "email", "job-runner", "observer", "synthetic"}:
            hardened[service] = {
                "user": container["Config"]["User"],
                "read_only": container["HostConfig"]["ReadonlyRootfs"],
                "cap_drop": container["HostConfig"].get("CapDrop"),
                "no_new_privileges": "no-new-privileges:true"
                in (container["HostConfig"].get("SecurityOpt") or []),
            }
            values = hardened[service]
            if (
                values["user"] != "65532:65532"
                or not values["read_only"]
                or values["cap_drop"] != ["ALL"]
                or not values["no_new_privileges"]
            ):
                raise RuntimeError(
                    f"service {service} is not running hardened: {values}"
                )
            destinations = {mount["Destination"] for mount in container["Mounts"]}
            mounts_by_destination = {
                mount["Destination"]: mount for mount in container["Mounts"]
            }
            expected_secret_mounts = {
                "/run/database-secrets",
                "/run/mail-edge",
                "/run/secrets",
            }
            if service == "synthetic":
                expected_secret_mounts.add("/run/operator-secrets")
            missing_secret_mounts = expected_secret_mounts - destinations
            unexpected_operator_mount = (
                service != "synthetic" and "/run/operator-secrets" in destinations
            )
            writable_secret_mounts = {
                destination
                for destination in expected_secret_mounts
                if destination in mounts_by_destination
                and mounts_by_destination[destination]["RW"]
            }
            secret_volume_mounts[service] = {
                "destinations": sorted(expected_secret_mounts & destinations),
                "operator_isolated": not unexpected_operator_mount,
                "read_only": not writable_secret_mounts,
            }
            if (
                missing_secret_mounts
                or unexpected_operator_mount
                or writable_secret_mounts
            ):
                raise RuntimeError(
                    f"service {service} has unsafe secret mounts: "
                    f"missing={sorted(missing_secret_mounts)}, "
                    f"operator_exposed={unexpected_operator_mount}, "
                    f"writable={sorted(writable_secret_mounts)}"
                )
            expected_secret_files = [
                "/run/database-secrets/postgres_password",
                "/run/mail-edge/config.json",
                "/run/secrets/flask_secret",
            ]
            if service == "synthetic":
                expected_secret_files.append("/run/operator-secrets/admin_password")
            file_access = json.loads(
                command(
                    "docker",
                    "exec",
                    container["Id"],
                    "/opt/venv/bin/python",
                    "-c",
                    "import json, os, stat, sys; from pathlib import Path; "
                    "print(json.dumps({path:{'owner':[Path(path).stat().st_uid,Path(path).stat().st_gid],"
                    "'mode':oct(stat.S_IMODE(Path(path).stat().st_mode)),'readable':os.access(path,os.R_OK)} "
                    "for path in sys.argv[1:]},sort_keys=True))",
                    *expected_secret_files,
                )
            )
            secret_file_access[service] = file_access
            invalid_secret_files = {
                path: values
                for path, values in file_access.items()
                if values
                != {"owner": [65532, 65532], "mode": "0o400", "readable": True}
            }
            if invalid_secret_files:
                raise RuntimeError(
                    f"service {service} has unsafe secret files: "
                    f"{invalid_secret_files}"
                )
            mail_edge_mounts[service] = {
                "config": "/run/mail-edge" in destinations,
                "spool": "/code/var/mail-edge-spool" in destinations,
            }
            if not all(mail_edge_mounts[service].values()):
                raise RuntimeError(
                    f"service {service} lacks Mail Edge mounts: {mail_edge_mounts[service]}"
                )
            volume_access = json.loads(
                command(
                    "docker",
                    "exec",
                    container["Id"],
                    "/opt/venv/bin/python",
                    "-c",
                    "import json, os; from pathlib import Path; "
                    "paths=('/code/static/upload','/code/var/unsent','/code/var/mail-edge-spool'); "
                    "print(json.dumps({path:{'owner':[Path(path).stat().st_uid,Path(path).stat().st_gid],"
                    "'writable':os.access(path,os.W_OK)} for path in paths},sort_keys=True))",
                )
            )
            writable_volume_paths[service] = volume_access
            invalid_volume_paths = {
                path: values
                for path, values in volume_access.items()
                if values != {"owner": [65532, 65532], "writable": True}
            }
            if invalid_volume_paths:
                raise RuntimeError(
                    f"service {service} has unsafe writable volume ownership: "
                    f"{invalid_volume_paths}"
                )
    missing_hardened = {
        "app",
        "email",
        "job-runner",
        "observer",
        "synthetic",
    } - hardened.keys()
    if missing_hardened:
        raise RuntimeError(f"hardened services not running: {sorted(missing_hardened)}")
    if not loopback_ports:
        raise RuntimeError("a published port is not bound to loopback")

    postgres = next(
        item
        for item in inspected
        if item["Config"]["Labels"].get("com.docker.compose.service") == "postgres"
    )
    postgres_mounts = {mount["Destination"]: mount for mount in postgres["Mounts"]}
    if (
        "/run/database-secrets" not in postgres_mounts
        or postgres_mounts["/run/database-secrets"]["RW"]
        or "/run/secrets" in postgres_mounts
        or "/run/operator-secrets" in postgres_mounts
    ):
        raise RuntimeError("PostgreSQL secret volume is not least-privilege read-only")
    secret_volume_mounts["postgres"] = {
        "destinations": ["/run/database-secrets"],
        "operator_isolated": True,
        "read_only": True,
    }

    leaked_logs = []
    pii_logs = {}
    service_by_id = {
        container["Id"]: container["Config"]["Labels"].get("com.docker.compose.service")
        for container in inspected
    }
    for container_id in container_ids:
        completed = subprocess.run(
            ["docker", "logs", "--tail", "2000", container_id],
            check=False,
            capture_output=True,
            text=True,
        )
        encoded_logs = completed.stdout + completed.stderr
        for name, value in secrets.items():
            if value and value in encoded_logs:
                leaked_logs.append(name)
        service = service_by_id.get(container_id)
        if service in {"app", "email", "job-runner", "observer", "synthetic"}:
            kinds = sorted(
                {
                    kind
                    for line in encoded_logs.splitlines()
                    for kind in sensitive_kinds(line)
                }
            )
            if kinds:
                pii_logs[str(service)] = kinds
    if leaked_logs:
        raise RuntimeError(
            f"secret values leaked into service logs: {sorted(set(leaked_logs))}"
        )
    if pii_logs:
        raise RuntimeError(f"raw PII/auth material remains in service logs: {pii_logs}")

    app_id = next(
        item["Id"]
        for item in inspected
        if item["Config"]["Labels"].get("com.docker.compose.service") == "app"
    )
    image = json.loads(
        command(
            "docker",
            "image",
            "inspect",
            command("docker", "inspect", "--format", "{{.Image}}", app_id),
        )
    )[0]
    image_id = image["Id"]
    labels = image["Config"].get("Labels", {})
    revision = labels.get("org.opencontainers.image.revision")
    upstream_revision = labels.get("org.opencontainers.image.upstream.revision")
    source = labels.get("org.opencontainers.image.source")
    license_expression = labels.get("org.opencontainers.image.licenses")
    source_date_epoch = labels.get("org.opencontainers.image.source-date-epoch")
    if revision != expected_revision:
        raise RuntimeError(
            f"image revision {revision} differs from {expected_revision}"
        )
    if upstream_revision != expected_upstream:
        raise RuntimeError(
            f"image upstream revision {upstream_revision} differs from {expected_upstream}"
        )
    expected_source = "https://github.com/mateoltd/simplelogin-owned-provider"
    if source != expected_source:
        raise RuntimeError(f"image source {source} differs from {expected_source}")
    if license_expression != "AGPL-3.0-only":
        raise RuntimeError(
            f"image license {license_expression} differs from AGPL-3.0-only"
        )
    expected_epoch = command(
        "git", "-C", str(repository), "show", "-s", "--format=%ct", "HEAD"
    )
    if source_date_epoch != expected_epoch:
        raise RuntimeError(
            f"image source date epoch {source_date_epoch} differs from {expected_epoch}"
        )

    build_info = json.loads(
        command(
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "/opt/venv/bin/python",
            image_id,
            "-c",
            "import json; from app.build_info import BUILD_TIME, SHA1; "
            "print(json.dumps({'revision': SHA1, 'source_date_epoch': BUILD_TIME}))",
        )
    )
    if build_info != {
        "revision": expected_revision,
        "source_date_epoch": expected_epoch,
    }:
        raise RuntimeError(
            f"runtime build provenance differs from OCI labels: {build_info}"
        )

    scan_script = r"""
import json
from pathlib import Path
import sys

secrets = {
    name: value.encode()
    for name, value in json.load(sys.stdin).items()
    if value
}
root = Path('/code')
if (root / '.owned-provider').exists():
    raise SystemExit('runtime directory is present in image')
forbidden_paths = (
    root / 'tests',
    root / '.env',
    root / 'local_data/private-pgp.asc',
    root / 'local_data/jwtRS256.key',
    root / 'local_data/dkim.key',
    root / 'local_data/key.pem',
    root / 'local_data/test_words.txt',
)
present = [str(path) for path in forbidden_paths if path.exists()]
if present:
    raise SystemExit('fixture or credential paths are present: ' + ', '.join(present))
upload_files = [
    str(path)
    for path in (root / 'static/upload').rglob('*')
    if path.is_file() or path.is_symlink()
]
if upload_files:
    raise SystemExit('preloaded upload files are present: ' + ', '.join(upload_files))
leaks = {}
overlap = max((len(value) for value in secrets.values()), default=1) - 1
for path in root.rglob('*'):
    if not path.is_file() or path.is_symlink():
        continue
    previous = b''
    try:
        with path.open('rb') as handle:
            while chunk := handle.read(1024 * 1024):
                payload = previous + chunk
                for name, value in secrets.items():
                    if value in payload:
                        leaks.setdefault(name, []).append(str(path))
                previous = payload[-overlap:] if overlap else b''
    except (OSError, PermissionError):
        raise SystemExit(f'cannot scan image file: {path}')
if leaks:
    print(json.dumps(leaks, sort_keys=True))
    raise SystemExit(1)
"""
    scan = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--interactive",
            "--entrypoint",
            "/opt/venv/bin/python",
            image_id,
            "-c",
            scan_script,
        ],
        input=json.dumps(secrets),
        capture_output=True,
        text=True,
        check=False,
    )
    if scan.returncode:
        raise RuntimeError(
            "runtime image contains generated state or a mounted secret value: "
            f"{scan.stdout.strip()} {scan.stderr.strip()}"
        )

    print(
        json.dumps(
            {
                "upstream_commit": expected_upstream,
                "owned_provider_and_mail_edge_diff_allowlisted": True,
                "secret_files_mode": "0600",
                "secrets_absent_from_docker_metadata": True,
                "loopback_only_ports": loopback_ports,
                "hardened_services": hardened,
                "secret_volume_mounts": secret_volume_mounts,
                "secret_file_access": secret_file_access,
                "mail_edge_mounts": mail_edge_mounts,
                "writable_volume_paths": writable_volume_paths,
                "secrets_absent_from_recent_logs": True,
                "pii_absent_from_recent_service_logs": True,
                "image_revision": revision,
                "image_upstream_revision": upstream_revision,
                "image_source": source,
                "image_license": license_expression,
                "image_source_date_epoch": source_date_epoch,
                "runtime_build_info_matches_labels": True,
                "runtime_state_and_secret_values_absent_from_image": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
