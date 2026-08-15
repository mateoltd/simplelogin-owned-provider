"""Audit local containment, secret exposure, container hardening, and provenance."""

import argparse
import json
import stat
import subprocess
from pathlib import Path


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

    expected = (repository / "ops/owned-provider/UPSTREAM_COMMIT").read_text().strip()
    subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", expected, "HEAD"],
        check=True,
    )
    changed = command(
        "git", "-C", str(repository), "diff", "--name-only", expected, "--"
    ).splitlines()
    exact_host_paths = {
        ".gitignore",
        "app/db.py",
        "app/email_utils.py",
        "app/mail_sender.py",
        "app/models.py",
        "docs/mail-edge-bridge.md",
        "email_handler.py",
        "simplelogin_app.py",
        "tests/conftest.py",
        "tests/test_email_utils.py",
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
            mail_edge_mounts[service] = {
                "config": "/run/mail-edge/config.json" in destinations,
                "spool": "/code/var/mail-edge-spool" in destinations,
            }
            if not all(mail_edge_mounts[service].values()):
                raise RuntimeError(
                    f"service {service} lacks Mail Edge mounts: {mail_edge_mounts[service]}"
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

    leaked_logs = []
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
    if leaked_logs:
        raise RuntimeError(
            f"secret values leaked into service logs: {sorted(set(leaked_logs))}"
        )

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
    revision = (
        image["Config"].get("Labels", {}).get("org.opencontainers.image.revision")
    )
    if revision != expected:
        raise RuntimeError(f"image revision {revision} differs from {expected}")

    print(
        json.dumps(
            {
                "upstream_commit": expected,
                "owned_provider_and_mail_edge_diff_allowlisted": True,
                "secret_files_mode": "0600",
                "secrets_absent_from_docker_metadata": True,
                "loopback_only_ports": loopback_ports,
                "hardened_services": hardened,
                "mail_edge_mounts": mail_edge_mounts,
                "secrets_absent_from_recent_logs": True,
                "image_revision": revision,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
