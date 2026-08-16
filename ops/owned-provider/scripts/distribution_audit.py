"""Fail closed on the compliance bundle for the exact local production image."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from distribution_bundle import (
    ComplianceBundleVerifier,
    DistributionPolicy,
    DockerImageInspector,
    validate_runtime_inventory,
)


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def default_bundle_path(repository: Path) -> Path:
    runtime = Path(
        os.environ.get("OWNED_PROVIDER_RUNTIME_DIR", repository / ".owned-provider")
    )
    return runtime / "evidence" / "distribution"


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument(
        "--policy",
        type=Path,
        default=script_dir.parent / "distribution-policy.toml",
    )
    args = parser.parse_args()
    repository = args.repository.resolve()
    bundle = (args.bundle or default_bundle_path(repository)).resolve()
    policy = DistributionPolicy.load(args.policy)

    if command(
        "git",
        "-C",
        str(repository),
        "status",
        "--porcelain",
        "--untracked-files=all",
    ):
        raise RuntimeError("distribution audit requires a clean source worktree")
    revision = command("git", "-C", str(repository), "rev-parse", "HEAD")
    source_date_epoch = command(
        "git", "-C", str(repository), "show", "-s", "--format=%ct", "HEAD"
    )
    upstream_revision = (
        (repository / "ops/owned-provider/UPSTREAM_COMMIT").read_text().strip()
    )

    inspector = DockerImageInspector()
    image = inspector.inspect_identity(args.image)
    required_labels = {
        "org.opencontainers.image.source": policy.fork_source_url,
        "org.opencontainers.image.upstream.source": policy.upstream_source_url,
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.upstream.revision": upstream_revision,
        "org.opencontainers.image.licenses": policy.license_expression,
        "org.opencontainers.image.source-date-epoch": source_date_epoch,
    }
    observed_labels = {name: image.labels.get(name) for name in required_labels}
    if observed_labels != required_labels:
        raise RuntimeError(
            f"production image provenance labels differ: {observed_labels}"
        )
    embedded = inspector.inspect_embedded_provenance(args.image)
    expected_embedded = {
        "revision": revision,
        "source_date_epoch": source_date_epoch,
        "owned_provider_runtime_present": False,
        "forbidden_fixture_paths_present": [],
        "static_upload_files_present": [],
    }
    if embedded != expected_embedded:
        raise RuntimeError(
            f"runtime provenance or generated-state exclusion differs: {embedded}"
        )
    runtime = inspector.inspect_runtime(args.image, policy, native_complete=True)
    validate_runtime_inventory(runtime, policy)
    native = inspector.inspect_native(args.image)
    result = ComplianceBundleVerifier(policy).verify(
        bundle,
        expected_image=image,
        expected_runtime=runtime,
        expected_native=native,
        expected_repository_revision=revision,
        expected_upstream_revision=upstream_revision,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
