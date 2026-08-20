from __future__ import annotations

import gzip
import io
import json
import base64
import sys
import tarfile
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[3]
SCRIPT_DIRECTORY = REPOSITORY / "ops" / "owned-provider" / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from public_release_bundle import (  # noqa: E402
    ArchiveMetadata,
    Component,
    PublicReleaseVerifier,
    ReleaseError,
    ReleasePolicy,
    build_checksum_manifest,
    canonical_json,
    copy_custom_license_references,
    cyclonedx_document,
    deterministic_directory_archive,
    inspect_archive,
    npm_lock_components,
    parse_checksum_manifest,
    parse_pnpm_lock,
    resolve_license,
    run_secret_scan,
    sha256_bytes,
    spdx_document,
    validate_relative_path,
    verify_secret_allowlist,
)

POLICY_PATH = REPOSITORY / "ops" / "owned-provider" / "public-release-policy.toml"


@pytest.fixture()
def policy() -> ReleasePolicy:
    return ReleasePolicy.load(POLICY_PATH)


def source_tar(files: dict[str, bytes]) -> bytes:
    uncompressed = io.BytesIO()
    with tarfile.open(fileobj=uncompressed, mode="w") as archive:
        for name, payload in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mtime = 0
            archive.addfile(member, io.BytesIO(payload))
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as stream:
        stream.write(uncompressed.getvalue())
    return output.getvalue()


def test_spdx_requires_reviewed_custom_license_text() -> None:
    component = Component(
        bom_ref="pkg:pypi/example@1",
        ecosystem="pypi",
        name="example",
        version="1",
        scope="runtime",
        license_expression="MIT OR LicenseRef-Example",
        license_evidence="test",
        source_url="https://example.invalid/example.tar.gz",
        integrity=sri(b"example"),
    )

    with pytest.raises(ReleaseError, match="custom license references are unreviewed"):
        spdx_document((component,), "https://example.invalid/spdx")

    document = spdx_document(
        (component,),
        "https://example.invalid/spdx",
        {"LicenseRef-Example": "Exact custom terms.\n"},
    )
    assert document["hasExtractedLicensingInfos"] == [
        {
            "extractedText": "Exact custom terms.\n",
            "licenseId": "LicenseRef-Example",
        }
    ]


def test_custom_license_text_must_match_archive_evidence(tmp_path: Path) -> None:
    component = Component(
        bom_ref="pkg:pypi/example@1",
        ecosystem="pypi",
        name="example",
        version="1",
        scope="runtime",
        license_expression="LicenseRef-Example",
        license_evidence="test",
        source_url="https://example.invalid/example.tar.gz",
        integrity=sri(b"example"),
    )
    metadata = ArchiveMetadata(
        license_expression=None,
        license_files=(("example/LICENSE", b"Actual custom terms.\n"),),
        package_name="example",
        package_version="1",
        raw_license=None,
        classifiers=(),
    )

    with pytest.raises(ReleaseError, match="differs from archive evidence"):
        copy_custom_license_references(
            tmp_path,
            component,
            metadata,
            {"LicenseRef-Example": "Different terms.\n"},
        )

    assert copy_custom_license_references(
        tmp_path,
        component,
        metadata,
        {"LicenseRef-Example": "Actual custom terms.\n"},
    ) == ("licenses/custom/LicenseRef-Example.txt",)


def sri(payload: bytes) -> str:
    return "sha256-" + base64.b64encode(bytes.fromhex(sha256_bytes(payload))).decode()


class SecretScanRunner:
    def __init__(self, version: str) -> None:
        self.version = version
        self.calls: list[tuple[str, ...]] = []
        self.working_directories: list[Path] = []

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        cwd: Path | None = None,
        text: bool = True,
    ) -> str:
        assert cwd is not None
        assert text is True
        if len(arguments) > 1 and arguments[1] == "dir":
            assert (cwd / "ops/owned-provider/gitleaks.toml").is_file()
            assert not (cwd / ".owned-provider").exists()
        self.calls.append(arguments)
        self.working_directories.append(cwd)
        return self.version if arguments[-1] == "version" else ""


def rewrite_checksums(bundle: Path) -> None:
    (bundle / "SHA256SUMS").write_bytes(build_checksum_manifest(bundle))


def rewrite_sboms(bundle: Path) -> None:
    graph = json.loads((bundle / "dependencies/graph.json").read_bytes())
    models = tuple(
        Component(
            **{
                **item,
                "dependencies": tuple(item["dependencies"]),
                "license_paths": tuple(item["license_paths"]),
            }
        )
        for item in graph["components"]
    )
    cdx_path = bundle / "sbom/bom.cdx.json"
    cdx = json.loads(cdx_path.read_bytes())
    cdx_path.write_bytes(
        canonical_json(
            cyclonedx_document(models, "pkg:generic/owned@1", cdx["serialNumber"])
        )
        + b"\n"
    )
    spdx_path = bundle / "sbom/bom.spdx.json"
    spdx = json.loads(spdx_path.read_bytes())
    spdx_path.write_bytes(
        canonical_json(spdx_document(models, spdx["documentNamespace"])) + b"\n"
    )


def make_complete_bundle(root: Path, policy: ReleasePolicy) -> Path:
    root.mkdir()
    owned_commit = "7" * 40
    edge_commit = "6" * 40
    clipboard = b"clipboard\n"
    base64_source = b"base64 source\n"
    webauthn_source = b"webauthn source\n"
    owned_archive = source_tar(
        {
            f"owned-provider-{owned_commit}/source.py": b"source\n",
            f"owned-provider-{owned_commit}/static/assets/js/vendors/base64.js": base64_source,
            f"owned-provider-{owned_commit}/static/assets/js/vendors/webauthn.js": webauthn_source,
            f"owned-provider-{owned_commit}/static/vendor/clipboard.min.js": clipboard,
        }
    )
    edge_archive = source_tar({f"mail-edge-{edge_commit}/source.ts": b"source\n"})
    paths = {
        "sources/projects/owned.tar.gz": owned_archive,
        "sources/projects/edge.tar.gz": edge_archive,
        "licenses/AGPL.txt": b"AGPL text\n",
        "licenses/Apache.txt": b"Apache text\n",
        "licenses/container/debian/base/copyright": b"Debian license text\n",
    }
    for relative, payload in paths.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    components = [
        {
            "bom_ref": "pkg:generic/owned@1",
            "dependencies": [],
            "ecosystem": "git",
            "integrity": sri(owned_archive),
            "license_evidence": "repository",
            "license_expression": "AGPL-3.0-only",
            "license_paths": ["licenses/AGPL.txt"],
            "name": "owned",
            "properties": {},
            "scope": "source",
            "source_archive_path": "sources/projects/owned.tar.gz",
            "source_url": "https://example.invalid/owned",
            "version": "1",
        },
        {
            "bom_ref": "pkg:generic/edge@1",
            "dependencies": [],
            "ecosystem": "git",
            "integrity": sri(edge_archive),
            "license_evidence": "repository",
            "license_expression": "Apache-2.0",
            "license_paths": ["licenses/Apache.txt"],
            "name": "edge",
            "properties": {},
            "scope": "source",
            "source_archive_path": "sources/projects/edge.tar.gz",
            "source_url": "https://example.invalid/edge",
            "version": "1",
        },
    ]
    for index in range(1111):
        if index < 115:
            ecosystem = "pypi"
            scope = "runtime"
            source_archive_path = "sources/projects/owned.tar.gz"
        elif index < 156:
            ecosystem = "npm"
            scope = "runtime"
            source_archive_path = "sources/projects/owned.tar.gz"
        elif index < 160:
            ecosystem = "vendored-npm"
            scope = "vendored"
            source_archive_path = "sources/projects/owned.tar.gz"
        else:
            ecosystem = "mail-edge-npm"
            scope = "production" if index < 351 else "build"
            source_archive_path = None
        components.append(
            {
                "bom_ref": f"pkg:generic/build-{index}@1",
                "dependencies": [],
                "ecosystem": ecosystem,
                "integrity": (
                    sri(owned_archive)
                    if source_archive_path
                    else sri(f"build-{index}".encode())
                ),
                "license_evidence": "archive",
                "license_expression": "MIT",
                "license_paths": [],
                "name": f"build-{index}",
                "properties": {},
                "scope": scope,
                "source_archive_path": source_archive_path,
                "source_url": f"https://example.invalid/build-{index}",
                "version": "1",
            }
        )
    graph = {
        "components": components,
        "counts": {
            "mail_edge_full_lock": 951,
            "mail_edge_production": 191,
            "owned_provider_npm_runtime": 41,
            "owned_provider_python_runtime": 115,
            "vendored": 4,
        },
        "lock_sha256": {
            "mail_edge_pnpm": "1" * 64,
            "owned_provider_npm": "2" * 64,
            "owned_provider_uv": "3" * 64,
            "reviewed_python_runtime": "4" * 64,
        },
        "schema": "owned-provider-dependency-graph-v1",
    }
    component_models = tuple(
        Component(
            **{
                **item,
                "dependencies": tuple(item["dependencies"]),
                "license_paths": tuple(item["license_paths"]),
            }
        )
        for item in components
    )
    cdx = cyclonedx_document(
        component_models,
        "pkg:generic/owned@1",
        "urn:uuid:11111111-1111-1111-1111-111111111111",
    )
    spdx = spdx_document(component_models, "https://example.invalid/spdx/test")
    provenance = {
        "bundle_format": policy.format_name,
        "distribution_scope": dict(policy.distribution_scope),
    }
    container = {
        "image": {"image_id": f"sha256:{'5' * 64}"},
        "runtime": {
            "debian_license_paths": ["licenses/container/debian/base/copyright"],
            "debian_scan_complete": True,
            "executable_scan_complete": True,
            "native_scan_complete": True,
            "npm_scan_complete": True,
            "python_scan_complete": True,
        },
    }
    reviewed_asset = policy.source_assets[0]
    static_assets = {
        "clipboard": {
            "exact": True,
            "path": "static/vendor/clipboard.min.js",
            "sha256": sha256_bytes(clipboard),
        },
        "schema": "owned-provider-static-asset-audit-v1",
        "source_assets": [
            {
                "license_expression": reviewed_asset["license_expression"],
                "name": reviewed_asset["name"],
                "paths": [
                    {
                        "path": "static/assets/js/vendors/base64.js",
                        "sha256": sha256_bytes(base64_source),
                    },
                    {
                        "path": "static/assets/js/vendors/webauthn.js",
                        "sha256": sha256_bytes(webauthn_source),
                    },
                ],
                "relationship": reviewed_asset["relationship"],
                "source_url": reviewed_asset["source_url"],
            }
        ],
        "tabler": {
            "exact_file_count": 477,
            "local_file_count": 481,
            "local_only": [
                "js/vendors/base64.js",
                "js/vendors/bootstrap.bundle.min.js.map",
                "js/vendors/webauthn.js",
            ],
            "modified": ["js/core.js"],
            "upstream_file_count": 478,
            "upstream_only": [],
        },
    }
    manifest = {
        "claims": {
            "legal_approval": False,
            "public_source_offer_created": False,
            "section_16_7_complete": False,
            "signatures_created": False,
        },
        "mail_edge_commit": edge_commit,
        "owned_provider_commit": owned_commit,
        "schema": "owned-provider-public-release-manifest-v1",
        "source_archives": {
            "mail_edge": {
                "path": "sources/projects/edge.tar.gz",
                "sha256": sha256_bytes(edge_archive),
            },
            "owned_provider": {
                "path": "sources/projects/owned.tar.gz",
                "sha256": sha256_bytes(owned_archive),
            },
        },
    }
    json_files = {
        "dependencies/graph.json": graph,
        "dependencies/static-assets.json": static_assets,
        "evidence/container-runtime.json": container,
        "MANIFEST.json": manifest,
        "PROVENANCE.json": provenance,
        "sbom/bom.cdx.json": cdx,
        "sbom/bom.spdx.json": spdx,
    }
    for relative, value in json_files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json(value) + b"\n")
    rewrite_checksums(root)
    return root


@pytest.mark.parametrize(
    "value",
    ["", "/absolute", "../escape", "safe/../escape", "windows\\path", "./dot"],
)
def test_relative_paths_fail_closed(value: str) -> None:
    with pytest.raises(ReleaseError):
        validate_relative_path(value)


def test_archive_rejects_root_escape(policy: ReleasePolicy) -> None:
    payload = source_tar({"../../escape": b"hostile"})
    with pytest.raises(ReleaseError, match="escapes"):
        inspect_archive(
            payload,
            maximum_members=policy.maximum_archive_members,
            maximum_license_bytes=policy.maximum_license_bytes,
            maximum_license_files=policy.maximum_license_files,
        )


def test_archive_allows_bounded_internal_parent(policy: ReleasePolicy) -> None:
    payload = source_tar(
        {
            "package/docs/../LICENSE": b"MIT License\n",
            "package/package.json": json.dumps(
                {"license": "MIT", "name": "example", "version": "1.0.0"}
            ).encode(),
        }
    )
    metadata = inspect_archive(
        payload,
        maximum_members=policy.maximum_archive_members,
        maximum_license_bytes=policy.maximum_license_bytes,
        maximum_license_files=policy.maximum_license_files,
    )
    assert metadata.license_expression == "MIT"
    assert metadata.license_files == (("package/LICENSE", b"MIT License\n"),)


def test_license_override_is_exact_and_reviewed() -> None:
    metadata = ArchiveMetadata(
        None, (("package/LICENSE", b"text"),), "toastr", "2.1.4", None, ()
    )
    expression, evidence = resolve_license(
        "npm", "toastr", "2.1.4", metadata, {"toastr@2.1.4": "MIT"}
    )
    assert expression == "MIT"
    assert evidence == "reviewed-policy-override"
    with pytest.raises(ReleaseError, match="no unambiguous"):
        resolve_license("npm", "toastr", "2.1.5", metadata, {})


def test_license_override_cannot_conflict_with_archive_metadata() -> None:
    metadata = ArchiveMetadata(
        "MIT", (("package/LICENSE", b"text"),), "example", "1.0.0", "MIT", ()
    )
    with pytest.raises(ReleaseError, match="override conflicts"):
        resolve_license(
            "npm", "example", "1.0.0", metadata, {"example@1.0.0": "Apache-2.0"}
        )


def test_pnpm_graph_includes_alias_and_production_closure() -> None:
    lock = b"""lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: 1.0.0
        version: real@1.0.0
packages:
  real@1.0.0:
    resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==}
snapshots:
  real@1.0.0: {}
"""
    graph = parse_pnpm_lock(lock, expected_full_count=1, expected_production_count=1)
    assert len(graph.components) == 1
    assert len(graph.production_refs) == 1


def test_repository_frontend_closure_is_reviewed() -> None:
    components = npm_lock_components(REPOSITORY)
    assert len(components) == 41
    assert all(component.scope == "runtime" for component in components)
    by_name = {component.name: component for component in components}
    assert {"@popperjs/core", "bootstrap", "jquery"}.issubset(by_name)
    assert by_name["bootstrap"].bom_ref in by_name["bootbox"].dependencies
    assert by_name["@popperjs/core"].bom_ref in by_name["bootbox"].dependencies
    assert by_name["jquery"].bom_ref in by_name["bootbox"].dependencies
    assert by_name["@popperjs/core"].bom_ref in by_name["bootstrap"].dependencies


def test_required_npm_peer_must_exist(tmp_path: Path) -> None:
    static = tmp_path / "static"
    static.mkdir()
    (static / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"root": "1.0.0"}},
                    "node_modules/root": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/root/-/root-1.0.0.tgz",
                        "integrity": sri(b"root"),
                        "peerDependencies": {"missing": "^1.0.0"},
                    },
                }
            }
        )
    )
    with pytest.raises(ReleaseError, match="required npm peer dependency is absent"):
        npm_lock_components(tmp_path)


def test_paddle_fallback_is_absent() -> None:
    assert not (REPOSITORY / "static/vendor/paddle.js").exists()
    for relative in (
        "templates/dashboard/coupon.html",
        "templates/dashboard/pricing.html",
    ):
        assert "/static/vendor/paddle.js" not in (REPOSITORY / relative).read_text()


def test_secret_allowlist_is_byte_pinned(policy: ReleasePolicy, tmp_path: Path) -> None:
    result = verify_secret_allowlist(REPOSITORY, policy)
    assert result["verified"] is True
    assert result["fixture_count"] == 7
    first = next(iter(policy.secret_fixture_hashes))
    hostile = tmp_path / first
    hostile.parent.mkdir(parents=True)
    hostile.write_text("substituted secret fixture\n")
    with pytest.raises(ReleaseError, match="fixture bytes changed"):
        verify_secret_allowlist(tmp_path, policy)


def test_secret_scan_pins_tool_and_runs_tree_and_history(
    policy: ReleasePolicy,
) -> None:
    runner = SecretScanRunner(policy.gitleaks_version)
    result = run_secret_scan(REPOSITORY, policy, Path("/reviewed/gitleaks"), runner)
    assert result == {
        "fixture_count": 7,
        "gitleaks_version": policy.gitleaks_version,
        "verified": True,
    }
    assert [call[1] for call in runner.calls] == ["version", "dir", "git"]
    assert runner.working_directories[0] == REPOSITORY
    assert runner.working_directories[1] != REPOSITORY
    assert runner.working_directories[2] == REPOSITORY
    stale = SecretScanRunner("0.0.0")
    with pytest.raises(ReleaseError, match="version differs"):
        run_secret_scan(REPOSITORY, policy, Path("/reviewed/gitleaks"), stale)


def test_complete_bundle_verifies(tmp_path: Path, policy: ReleasePolicy) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    result = PublicReleaseVerifier(policy).verify(bundle)
    assert result["verified"] is True
    assert result["component_count"] == 1113


def test_tampered_payload_is_rejected(tmp_path: Path, policy: ReleasePolicy) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    (bundle / "licenses/AGPL.txt").write_text("tampered\n")
    with pytest.raises(ReleaseError, match="checksum mismatch"):
        PublicReleaseVerifier(policy).verify(bundle)


def test_missing_file_with_rewritten_sums_is_rejected(
    tmp_path: Path, policy: ReleasePolicy
) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    (bundle / "licenses/AGPL.txt").unlink()
    rewrite_checksums(bundle)
    with pytest.raises(ReleaseError, match="license evidence is missing"):
        PublicReleaseVerifier(policy).verify(bundle)


def test_license_mismatch_with_rewritten_sums_is_rejected(
    tmp_path: Path, policy: ReleasePolicy
) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    graph_path = bundle / "dependencies/graph.json"
    graph = json.loads(graph_path.read_bytes())
    graph["components"][0]["license_expression"] = ""
    graph_path.write_bytes(canonical_json(graph) + b"\n")
    rewrite_checksums(bundle)
    with pytest.raises(ReleaseError, match="component license is missing"):
        PublicReleaseVerifier(policy).verify(bundle)


def test_false_legal_claim_with_rewritten_sums_is_rejected(
    tmp_path: Path, policy: ReleasePolicy
) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["claims"]["legal_approval"] = True
    manifest_path.write_bytes(canonical_json(manifest) + b"\n")
    rewrite_checksums(bundle)
    with pytest.raises(ReleaseError, match="unsupported release claim"):
        PublicReleaseVerifier(policy).verify(bundle)


def test_static_asset_mismatch_with_rewritten_sums_is_rejected(
    tmp_path: Path, policy: ReleasePolicy
) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    audit_path = bundle / "dependencies/static-assets.json"
    audit = json.loads(audit_path.read_bytes())
    audit["clipboard"]["sha256"] = "0" * 64
    audit_path.write_bytes(canonical_json(audit) + b"\n")
    rewrite_checksums(bundle)
    with pytest.raises(ReleaseError, match="clipboard evidence differs"):
        PublicReleaseVerifier(policy).verify(bundle)


def test_sbom_mismatch_with_rewritten_sums_is_rejected(
    tmp_path: Path, policy: ReleasePolicy
) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    cdx_path = bundle / "sbom/bom.cdx.json"
    cdx = json.loads(cdx_path.read_bytes())
    cdx["components"][0]["name"] = "substituted"
    cdx_path.write_bytes(canonical_json(cdx) + b"\n")
    rewrite_checksums(bundle)
    with pytest.raises(ReleaseError, match="CycloneDX component differs"):
        PublicReleaseVerifier(policy).verify(bundle)


def test_prohibited_source_member_with_rewritten_sums_is_rejected(
    tmp_path: Path, policy: ReleasePolicy
) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    archive_path = bundle / "sources/projects/owned.tar.gz"
    archive_path.write_bytes(
        source_tar({"owned/static/vendor/paddle.js": b"proprietary fallback"})
    )
    graph_path = bundle / "dependencies/graph.json"
    graph = json.loads(graph_path.read_bytes())
    replacement_integrity = sri(archive_path.read_bytes())
    for component in graph["components"]:
        if component["source_archive_path"] == "sources/projects/owned.tar.gz":
            component["integrity"] = replacement_integrity
    graph_path.write_bytes(canonical_json(graph) + b"\n")
    rewrite_sboms(bundle)
    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["source_archives"]["owned_provider"]["sha256"] = sha256_bytes(
        archive_path.read_bytes()
    )
    manifest_path.write_bytes(canonical_json(manifest) + b"\n")
    rewrite_checksums(bundle)
    with pytest.raises(ReleaseError, match="prohibited path"):
        PublicReleaseVerifier(policy).verify(bundle)


def test_noncanonical_json_is_rejected(tmp_path: Path, policy: ReleasePolicy) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    manifest_path = bundle / "MANIFEST.json"
    manifest_path.write_text(
        json.dumps(json.loads(manifest_path.read_bytes()), indent=2)
    )
    rewrite_checksums(bundle)
    with pytest.raises(ReleaseError, match="not canonical"):
        PublicReleaseVerifier(policy).verify(bundle)


def test_stale_lock_is_rejected(tmp_path: Path, policy: ReleasePolicy) -> None:
    bundle = make_complete_bundle(tmp_path / "bundle", policy)
    repository = tmp_path / "repository"
    (repository / "static").mkdir(parents=True)
    (repository / "uv.lock").write_text("stale\n")
    (repository / "static/package-lock.json").write_text("{}\n")
    with pytest.raises(ReleaseError, match="stale for the owned-provider uv.lock"):
        PublicReleaseVerifier(policy).verify(bundle, repository=repository)


def test_checksum_manifest_rejects_duplicate_and_unsorted_lines() -> None:
    payload = f"{'1' * 64}  b\n{'2' * 64}  a\n".encode()
    with pytest.raises(ReleaseError, match="strictly sorted"):
        parse_checksum_manifest(payload)


def test_checksum_manifest_sorts_complete_relative_paths(tmp_path: Path) -> None:
    nested = tmp_path / "foo"
    nested.mkdir()
    (nested / "bar").write_text("nested\n")
    (tmp_path / "foo.txt").write_text("sibling\n")

    manifest = build_checksum_manifest(tmp_path)

    assert list(parse_checksum_manifest(manifest)) == ["foo.txt", "foo/bar"]


def test_archive_is_independent_of_output_directory_name(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "evidence.txt").write_text("same\n")
    (second / "evidence.txt").write_text("same\n")
    first_archive = tmp_path / "first.tar.gz"
    second_archive = tmp_path / "second.tar.gz"
    deterministic_directory_archive(first, first_archive, 123)
    deterministic_directory_archive(second, second_archive, 123)
    assert first_archive.read_bytes() == second_archive.read_bytes()
