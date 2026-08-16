"""Fail closed on packaged license metadata, tooling, and source provenance."""

from __future__ import annotations

import argparse
import json
import subprocess
import tomllib
from pathlib import Path
from typing import Any


SOURCE_URL = "https://github.com/mateoltd/simplelogin-owned-provider"
LICENSE_EXPRESSION = "AGPL-3.0-only"
FORBIDDEN_DISTRIBUTIONS = {
    "astroid",
    "black",
    "djlint",
    "pylint",
    "pytest",
    "tqdm",
    "virtualenv",
}
REQUIRED_COPYLEFT_DISTRIBUTIONS = {
    "chardet",
    "crontab",
    "jwcrypto",
    "psycopg2-binary",
    "unidecode",
}


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def container_command(image: str, executable: str, *args: str) -> str:
    return command(
        "docker",
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "--entrypoint",
        executable,
        image,
        *args,
    )


def load_image(image: str) -> dict[str, Any]:
    inspected = json.loads(command("docker", "image", "inspect", image))
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise RuntimeError(f"expected one image inspection result for {image}")
    return inspected[0]


def read_project_license(repository: Path) -> str:
    with (repository / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    return str(project["license"])


def read_frontend_metadata(repository: Path) -> tuple[str, str, str]:
    package = json.loads((repository / "static/package.json").read_text())
    lock = json.loads((repository / "static/package-lock.json").read_text())
    return (
        str(package["license"]),
        str(lock["dependencies"]["intro.js"]["version"]),
        str(lock["dependencies"]["qrious"]["version"]),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()

    if command("git", "-C", str(repository), "status", "--porcelain"):
        raise RuntimeError("distribution audit requires a clean source worktree")

    revision = command("git", "-C", str(repository), "rev-parse", "HEAD")
    upstream_revision = (
        (repository / "ops/owned-provider/UPSTREAM_COMMIT").read_text().strip()
    )
    if "GNU AFFERO GENERAL PUBLIC LICENSE" not in (repository / "LICENSE").read_text():
        raise RuntimeError("root LICENSE is not the declared AGPL license")
    project_license = read_project_license(repository)
    frontend_license, intro_version, qrious_version = read_frontend_metadata(repository)
    if {project_license, frontend_license} != {LICENSE_EXPRESSION}:
        raise RuntimeError(
            "Python and frontend metadata must both declare AGPL-3.0-only"
        )

    image = load_image(args.image)
    labels = image.get("Config", {}).get("Labels", {})
    expected_labels = {
        "org.opencontainers.image.licenses": LICENSE_EXPRESSION,
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.source": SOURCE_URL,
        "org.opencontainers.image.upstream.revision": upstream_revision,
    }
    actual_labels = {key: labels.get(key) for key in expected_labels}
    if actual_labels != expected_labels:
        raise RuntimeError(
            f"image provenance labels differ: {actual_labels} != {expected_labels}"
        )

    installed = json.loads(
        container_command(
            args.image,
            "/code/.venv/bin/python",
            "-c",
            "import importlib.metadata as m,json; "
            "print(json.dumps(sorted({d.metadata['Name'].lower(): d.version "
            "for d in m.distributions()}.items())))",
        )
    )
    installed_names = {str(name) for name, _version in installed}
    forbidden = sorted(installed_names & FORBIDDEN_DISTRIBUTIONS)
    if forbidden:
        raise RuntimeError(f"development distributions shipped: {forbidden}")
    missing_copyleft = sorted(REQUIRED_COPYLEFT_DISTRIBUTIONS - installed_names)
    if missing_copyleft:
        raise RuntimeError(
            f"expected runtime copyleft inventory changed: {missing_copyleft}"
        )

    tools = container_command(
        args.image,
        "/bin/sh",
        "-c",
        "for name in gcc git gpg tar; do "
        'if command -v "$name" >/dev/null; then printf \'%s=present\\n\' "$name"; '
        "else printf '%s=absent\\n' \"$name\"; fi; done",
    )
    tool_inventory = dict(line.split("=", 1) for line in tools.splitlines())
    if tool_inventory != {
        "gcc": "absent",
        "git": "absent",
        "gpg": "present",
        "tar": "present",
    }:
        raise RuntimeError(f"unexpected runtime tool inventory: {tool_inventory}")

    print(
        json.dumps(
            {
                "development_distributions_absent": True,
                "frontend_copyleft": {
                    "intro.js": intro_version,
                    "qrious": qrious_version,
                },
                "image_labels": actual_labels,
                "python_copyleft_inventory": sorted(REQUIRED_COPYLEFT_DISTRIBUTIONS),
                "runtime_tools": tool_inventory,
                "source_metadata_license": LICENSE_EXPRESSION,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
