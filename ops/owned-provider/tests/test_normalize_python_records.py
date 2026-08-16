from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[3]
SCRIPT_DIRECTORY = REPOSITORY / "ops" / "owned-provider" / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from normalize_python_records import (  # noqa: E402
    RecordNormalizationError,
    hashed_file,
    normalized_record,
)


def test_normalized_record_recomputes_hashes(tmp_path: Path) -> None:
    environment = tmp_path / "venv"
    site_packages = environment / "lib" / "python3.12" / "site-packages"
    package = site_packages / "example"
    distribution = site_packages / "example-1.0.dist-info"
    package.mkdir(parents=True)
    distribution.mkdir()
    module = package / "module.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    record = distribution / "RECORD"
    record.write_text(
        "example/module.py,sha256=stale,1\n"
        "example-1.0.dist-info/RECORD,sha256=stale,1\n",
        encoding="utf-8",
    )

    rows = list(csv.reader(io.StringIO(normalized_record(record, site_packages))))

    digest, size = hashed_file(module)
    assert rows == [
        ["example/module.py", digest, size],
        ["example-1.0.dist-info/RECORD", "", ""],
    ]


def test_normalized_record_rejects_environment_escape(tmp_path: Path) -> None:
    site_packages = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    distribution = site_packages / "example-1.0.dist-info"
    distribution.mkdir(parents=True)
    record = distribution / "RECORD"
    record.write_text("../../../../../outside,sha256=stale,1\n", encoding="utf-8")

    with pytest.raises(RecordNormalizationError, match="escapes"):
        normalized_record(record, site_packages)
