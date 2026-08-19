"""Derive collision-resistant Docker Compose names for owned-provider runtimes."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def validate_project_name(value: str) -> str:
    """Return an exact operator-supplied name or reject unsafe Compose input."""

    if not PROJECT_NAME.fullmatch(value):
        raise ValueError(
            "project name must be 1-63 lower-case letters, digits, underscores, "
            "or hyphens and start with a letter or digit"
        )
    return value


def derive_project_name(repository: Path, runtime: Path) -> str:
    """Map one canonical repository/runtime pair to a stable private namespace."""

    identity = b"\0".join(
        (str(repository.resolve()).encode(), str(runtime.resolve()).encode())
    )
    digest = hashlib.sha256(identity).hexdigest()[:20]
    return f"sl-owned-{digest}"


def project_name(repository: Path, runtime: Path, explicit: str | None) -> str:
    if explicit:
        return validate_project_name(explicit)
    return derive_project_name(repository, runtime)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--explicit")
    args = parser.parse_args()
    try:
        print(project_name(args.repository, args.runtime, args.explicit))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
