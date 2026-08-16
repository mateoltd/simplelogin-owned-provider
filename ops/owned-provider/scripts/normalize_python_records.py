#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
from pathlib import Path, PurePosixPath


class RecordNormalizationError(ValueError):
    """Raised when an installed-wheel record points outside its environment."""


def hashed_file(path: Path) -> tuple[str, str]:
    digest = base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest())
    return f"sha256={digest.rstrip(b'=').decode('ascii')}", str(path.stat().st_size)


def installed_path(site_packages: Path, relative_name: str) -> Path:
    relative = PurePosixPath(relative_name)
    if relative.is_absolute():
        raise RecordNormalizationError("RECORD paths must be relative")
    environment_root = site_packages.parents[2].resolve()
    candidate = (site_packages / Path(*relative.parts)).resolve()
    if candidate != environment_root and environment_root not in candidate.parents:
        raise RecordNormalizationError("RECORD path escapes the virtual environment")
    return candidate


def normalized_record(record_path: Path, site_packages: Path) -> str:
    rows = list(csv.reader(io.StringIO(record_path.read_text(encoding="utf-8"))))
    normalized: list[list[str]] = []
    for row in rows:
        if len(row) != 3 or not row[0]:
            raise RecordNormalizationError("RECORD rows must have three fields")
        target = installed_path(site_packages, row[0])
        if target == record_path.resolve():
            normalized.append([row[0], "", ""])
        elif target.is_file():
            digest, size = hashed_file(target)
            normalized.append([row[0], digest, size])
        else:
            raise RecordNormalizationError(f"recorded file is missing: {row[0]}")
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(normalized)
    return output.getvalue()


def normalize_record(record_path: Path, site_packages: Path) -> None:
    record_path.write_text(
        normalized_record(record_path.resolve(), site_packages.resolve()),
        encoding="utf-8",
        newline="",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recompute installed-wheel RECORD hashes after deterministic stripping"
    )
    parser.add_argument("--site-packages", type=Path, required=True)
    parser.add_argument("record", type=Path, nargs="+")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    for record_path in args.record:
        normalize_record(record_path, args.site_packages)


if __name__ == "__main__":
    main()
