from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY / "ops" / "owned-provider" / "scripts"))

from runtime_namespace import (  # noqa: E402
    derive_project_name,
    project_name,
    validate_project_name,
)


def test_derived_namespace_is_stable_and_runtime_specific(tmp_path: Path):
    repository = tmp_path / "repository"
    first_runtime = tmp_path / "runtime-a"
    second_runtime = tmp_path / "runtime-b"

    first = derive_project_name(repository, first_runtime)

    assert first == derive_project_name(repository, first_runtime)
    assert first != derive_project_name(repository, second_runtime)
    assert first.startswith("sl-owned-")
    assert len(first) == 29


def test_explicit_namespace_is_exact_and_validated(tmp_path: Path):
    assert (
        project_name(tmp_path, tmp_path, "operator_runtime-2") == "operator_runtime-2"
    )
    assert validate_project_name("a") == "a"

    for invalid in ("", "Uppercase", "-leading", "contains.dot", "a" * 64):
        with pytest.raises(ValueError):
            validate_project_name(invalid)
