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
    unexpected = [
        path
        for path in changed
        if path != ".gitignore" and not path.startswith("ops/owned-provider/")
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
    loopback_ports = True
    for container in inspected:
        service = container["Config"]["Labels"].get("com.docker.compose.service")
        bindings = container["HostConfig"].get("PortBindings") or {}
        for values in bindings.values():
            for binding in values or []:
                if binding.get("HostIp") not in ("127.0.0.1", "::1"):
                    loopback_ports = False
        if service in {"app", "email", "job-runner"}:
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
    missing_hardened = {"app", "email", "job-runner"} - hardened.keys()
    if missing_hardened:
        raise RuntimeError(f"hardened services not running: {sorted(missing_hardened)}")
    if not loopback_ports:
        raise RuntimeError("a published port is not bound to loopback")

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
                "operations_only_diff": True,
                "secret_files_mode": "0600",
                "secrets_absent_from_docker_metadata": True,
                "loopback_only_ports": loopback_ports,
                "hardened_services": hardened,
                "image_revision": revision,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
