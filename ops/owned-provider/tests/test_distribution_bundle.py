from __future__ import annotations

import gzip
import io
import json
import sys
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[3]
SCRIPT_DIRECTORY = REPOSITORY / "ops" / "owned-provider" / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from distribution_bundle import (  # noqa: E402
    BundleInput,
    ComplianceBundleBuilder,
    ComplianceBundleVerifier,
    ComplianceError,
    ComponentRecord,
    DistributionPolicy,
    DockerImageInspector,
    ImageIdentity,
    NativeDependency,
    NativeRecord,
    ObservedNativeRecord,
    ProvenanceRecord,
    RelinkRecord,
    RuntimeInventory,
    SourceMaterial,
    build_checksum_manifest,
    parse_checksum_manifest,
    read_artifacts,
    sha256_bytes,
    validate_bundle_input,
    validate_license,
    validate_relative_path,
    validate_source_archive,
    validate_url,
)

POLICY_PATH = REPOSITORY / "ops" / "owned-provider" / "distribution-policy.toml"
FORK_REVISION = "1" * 40
UPSTREAM_REVISION = "2" * 40
IMAGE_ID = f"sha256:{'3' * 64}"
ROOTFS_ID = f"sha256:{'4' * 64}"


def source_tar(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, payload in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


@pytest.fixture()
def policy() -> DistributionPolicy:
    return DistributionPolicy.load(POLICY_PATH)


@pytest.fixture()
def complete_bundle(policy: DistributionPolicy) -> tuple[BundleInput, dict[str, bytes]]:
    root_source = source_tar({"owned-provider/README": b"source\n"})
    library_source = source_tar({"library/COPYING": b"LGPL source\n"})
    components = (
        ComponentRecord(
            bom_ref="pkg:generic/owned-provider@1.0.0",
            name="owned-provider",
            version="1.0.0",
            component_type="application",
            ecosystem="generic",
            purl="pkg:generic/owned-provider@1.0.0",
            license_expression="AGPL-3.0-only",
            license_path="licenses/owned-provider.txt",
            source_url=policy.fork_source_url,
            source_materials=(
                SourceMaterial(
                    path="sources/owned-provider.tar",
                    download_url=f"{policy.fork_source_url}/archive/{FORK_REVISION}.tar.gz",
                    sha256=sha256_bytes(root_source),
                ),
            ),
            installed_sha256="5" * 64,
            copyright_notice="Copyright Example",
            dependencies=("pkg:pypi/lgpl-library@2.0.0", "pkg:pypi/mit-library@3.0.0"),
        ),
        ComponentRecord(
            bom_ref="pkg:pypi/lgpl-library@2.0.0",
            name="lgpl-library",
            version="2.0.0",
            component_type="library",
            ecosystem="pypi",
            purl="pkg:pypi/lgpl-library@2.0.0",
            license_expression="LGPL-3.0-or-later",
            license_path="licenses/lgpl-library.txt",
            source_url="https://example.com/lgpl-library",
            source_materials=(
                SourceMaterial(
                    path="sources/lgpl-library.tar",
                    download_url="https://example.com/lgpl-library-2.0.0.tar.gz",
                    sha256=sha256_bytes(library_source),
                ),
            ),
            installed_sha256="6" * 64,
        ),
        ComponentRecord(
            bom_ref="pkg:pypi/mit-library@3.0.0",
            name="mit-library",
            version="3.0.0",
            component_type="library",
            ecosystem="pypi",
            purl="pkg:pypi/mit-library@3.0.0",
            license_expression="MIT",
            license_path="licenses/mit-library.txt",
            source_url="https://example.com/mit-library",
        ),
    )
    native = (
        NativeRecord(
            path="/code/.venv/lib/lgpl-library.so",
            sha256="7" * 64,
            owner_ref="pkg:pypi/lgpl-library@2.0.0",
            dependencies=(
                NativeDependency(
                    soname="libsystem.so.1", resolved_path="/usr/lib/libsystem.so.1"
                ),
            ),
        ),
        NativeRecord(
            path="/usr/lib/libsystem.so.1",
            sha256="8" * 64,
            owner_ref="pkg:deb/ubuntu/libsystem1@1.0",
        ),
    )
    system_component = ComponentRecord(
        bom_ref="pkg:deb/ubuntu/libsystem1@1.0",
        name="libsystem1",
        version="1.0",
        component_type="library",
        ecosystem="deb",
        purl="pkg:deb/ubuntu/libsystem1@1.0",
        license_expression="MIT",
        license_path="licenses/libsystem1.txt",
        source_url="https://packages.ubuntu.com/source/jammy/libsystem",
    )
    npm_component = ComponentRecord(
        bom_ref="pkg:npm/npm-library@4.0.0",
        name="npm-library",
        version="4.0.0",
        component_type="library",
        ecosystem="npm",
        purl="pkg:npm/npm-library@4.0.0",
        license_expression="MIT",
        license_path="licenses/npm-library.txt",
        source_url="https://www.npmjs.com/package/npm-library",
    )
    components += (system_component, npm_component)
    runtime = RuntimeInventory(
        python_distributions=("lgpl-library==2.0.0", "mit-library==3.0.0"),
        debian_packages=("libsystem1==1.0",),
        npm_packages=("npm-library@4.0.0",),
        executable_names=("bash", "gpg", "tar"),
        python_scan_complete=True,
        debian_scan_complete=True,
        npm_scan_complete=True,
        executable_scan_complete=True,
        native_scan_complete=True,
    )
    image = ImageIdentity(
        image_reference=f"simplelogin-owned-provider:{FORK_REVISION}",
        image_id=IMAGE_ID,
        platform="linux/amd64",
        rootfs_diff_ids=(ROOTFS_ID,),
        labels={
            "org.opencontainers.image.licenses": policy.license_expression,
            "org.opencontainers.image.revision": FORK_REVISION,
            "org.opencontainers.image.source": policy.fork_source_url,
            "org.opencontainers.image.upstream.revision": UPSTREAM_REVISION,
        },
    )
    value = BundleInput(
        provenance=ProvenanceRecord(
            repository_revision=FORK_REVISION,
            upstream_revision=UPSTREAM_REVISION,
            image=image,
            root_component_ref="pkg:generic/owned-provider@1.0.0",
            runtime=runtime,
        ),
        components=components,
        native=native,
        relinking=(
            RelinkRecord(
                component_ref="pkg:pypi/lgpl-library@2.0.0",
                linkage="dynamic",
                consumers=("/code/.venv/lib/lgpl-library.so",),
                instructions_path="relink/README.md",
                material_paths=("sources/lgpl-library.tar", "relink/README.md"),
                material_kinds=("source", "instructions"),
            ),
        ),
    )
    artifacts = {
        "licenses/owned-provider.txt": b"AGPL license\n",
        "licenses/lgpl-library.txt": b"LGPL license\n",
        "licenses/mit-library.txt": b"MIT license\n",
        "licenses/libsystem1.txt": b"MIT license\n",
        "licenses/npm-library.txt": b"MIT license\n",
        "sources/owned-provider.tar": root_source,
        "sources/lgpl-library.tar": library_source,
        "relink/README.md": b"Use the separate builder and replace the shared library.\n",
    }
    return value, artifacts


def bundle_files(path: Path) -> dict[str, bytes]:
    return {
        item.relative_to(path).as_posix(): item.read_bytes()
        for item in path.rglob("*")
        if item.is_file()
    }


def refresh_checksums(path: Path) -> None:
    files = bundle_files(path)
    files.pop("SHA256SUMS")
    (path / "SHA256SUMS").write_bytes(build_checksum_manifest(files))


def observed_native(value: BundleInput) -> tuple[ObservedNativeRecord, ...]:
    return tuple(
        ObservedNativeRecord(
            path=record.path,
            sha256=record.sha256,
            dependencies=record.dependencies,
        )
        for record in value.native
    )


def test_bundle_is_deterministic_and_bound_to_image(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    first = ComplianceBundleBuilder(policy).build(value, artifacts, tmp_path / "first")
    second = ComplianceBundleBuilder(policy).build(
        replace(value, components=tuple(reversed(value.components))),
        dict(reversed(tuple(artifacts.items()))),
        tmp_path / "second",
    )

    assert bundle_files(first) == bundle_files(second)
    result = ComplianceBundleVerifier(policy).verify(
        first,
        expected_image=value.provenance.image,
        expected_runtime=value.provenance.runtime,
        expected_native=observed_native(value),
        expected_repository_revision=FORK_REVISION,
        expected_upstream_revision=UPSTREAM_REVISION,
    )
    assert result["verified"] is True
    assert result["component_count"] == 5
    sbom = json.loads((first / "sbom.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert "timestamp" not in sbom["metadata"]


@pytest.mark.parametrize(
    "relative",
    ("../escape", "/absolute", "a/../../escape", "a\\b", "a/./b", "a\nb", ""),
)
def test_bundle_paths_fail_closed(relative: str) -> None:
    with pytest.raises(ComplianceError):
        validate_relative_path(relative)


@pytest.mark.parametrize(
    "url",
    (
        "http://example.com/source.tar.gz",
        "https://localhost/source.tar.gz",
        "https://127.0.0.1/source.tar.gz",
        "https://example.com/source.tar.gz?token=secret",
        "https://user@example.com/source.tar.gz",
    ),
)
def test_source_urls_must_be_public_credential_free_https(url: str) -> None:
    with pytest.raises(ComplianceError):
        validate_url(url, field_name="source URL")


def test_unknown_or_unreviewed_license_identifier_fails_closed(
    policy: DistributionPolicy,
) -> None:
    with pytest.raises(ComplianceError, match="unapproved SPDX"):
        validate_license("M1T", policy)
    with pytest.raises(ComplianceError, match="unapproved license reference"):
        validate_license("LicenseRef-unreviewed", policy)


def test_source_archive_rejects_path_traversal() -> None:
    payload = source_tar({"../../escape": b"bad"})
    with pytest.raises(ComplianceError, match="escapes"):
        validate_source_archive("sources/bad.tar", payload)


def test_posix_tar_member_may_contain_a_literal_backslash() -> None:
    payload = source_tar({r"source/dev-mapper\x2dswap.swap": b"fixture"})
    validate_source_archive("sources/systemd.tar", payload)


def test_source_archive_rejects_escaping_symlink() -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        link = tarfile.TarInfo("source/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)
    with pytest.raises(ComplianceError, match="link escapes"):
        validate_source_archive("sources/bad.tar", output.getvalue())


def test_debian_source_control_requires_signed_multipart_metadata() -> None:
    payload = b"""-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Format: 3.0 (quilt)
Source: native-library
Files:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 native-library.orig.tar.xz
Checksums-Sha256:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 native-library.orig.tar.xz
-----BEGIN PGP SIGNATURE-----
placeholder
-----END PGP SIGNATURE-----
"""
    validate_source_archive("sources/native-library.dsc", payload)
    with pytest.raises(ComplianceError, match="not clear-signed"):
        validate_source_archive(
            "sources/native-library.dsc",
            payload.replace(b"-----BEGIN PGP SIGNATURE-----", b"signature"),
        )


def test_debian_legacy_source_diff_is_bounded_and_validated() -> None:
    payload = gzip.compress(b"--- old/file\n+++ new/file\n@@ -1 +1 @@\n-old\n+new\n")
    validate_source_archive("sources/package.diff.gz", payload)

    with pytest.raises(ComplianceError, match="no unified patch"):
        validate_source_archive("sources/package.diff.gz", gzip.compress(b"notes\n"))


def test_missing_or_changed_source_fails_closed(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    missing = dict(artifacts)
    missing.pop("sources/owned-provider.tar")
    with pytest.raises(ComplianceError, match="artifact set differs"):
        ComplianceBundleBuilder(policy).build(value, missing, tmp_path / "missing")

    changed = dict(artifacts)
    changed["sources/owned-provider.tar"] += b"changed"
    with pytest.raises(ComplianceError, match="source digest differs"):
        ComplianceBundleBuilder(policy).build(value, changed, tmp_path / "changed")


def test_missing_exact_sources_can_be_retrieved_without_mutating_artifact_root(
    tmp_path: Path,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    source_payloads = {
        material.sha256: artifacts[material.path]
        for component in value.components
        for material in component.source_materials
    }
    for relative, payload in artifacts.items():
        if relative.startswith("sources/"):
            continue
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

    class FakeRetriever:
        def retrieve(self, request: object) -> bytes:
            return source_payloads[getattr(request, "digest")]

    loaded = read_artifacts(
        tmp_path,
        value,
        fetch_sources=True,
        retriever=FakeRetriever(),  # type: ignore[arg-type]
    )
    assert loaded == artifacts
    assert not (tmp_path / "sources").exists()


def test_copyleft_source_and_lgpl_relinking_are_mandatory(
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, _artifacts = complete_bundle
    lgpl = value.components[1]
    without_source = replace(
        lgpl,
        source_materials=(),
    )
    with pytest.raises(ComplianceError, match="lacks exact source"):
        validate_bundle_input(
            replace(
                value,
                components=(value.components[0], without_source, *value.components[2:]),
            ),
            policy,
        )
    with pytest.raises(ComplianceError, match="relinking coverage"):
        validate_bundle_input(replace(value, relinking=()), policy)


def test_multipart_corresponding_source_is_preserved(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    second_payload = source_tar({"library/debian/patches/fix.patch": b"patch\n"})
    second_material = SourceMaterial(
        path="sources/lgpl-library-debian.tar",
        download_url="https://example.com/lgpl-library-2.0.0-debian.tar.gz",
        sha256=sha256_bytes(second_payload),
    )
    lgpl = replace(
        value.components[1],
        source_materials=(*value.components[1].source_materials, second_material),
    )
    relink = replace(
        value.relinking[0],
        material_paths=(
            "sources/lgpl-library.tar",
            second_material.path,
            "relink/README.md",
        ),
        material_kinds=("source", "source", "instructions"),
    )
    updated = replace(
        value,
        components=(value.components[0], lgpl, *value.components[2:]),
        relinking=(relink,),
    )
    updated_artifacts = {**artifacts, second_material.path: second_payload}
    bundle = ComplianceBundleBuilder(policy).build(
        updated, updated_artifacts, tmp_path / "multipart"
    )
    result = ComplianceBundleVerifier(policy).verify(bundle)
    assert result["verified"] is True
    manifest = json.loads((bundle / "SOURCE_MANIFEST.json").read_text())
    lgpl_manifest = next(
        component
        for component in manifest["components"]
        if component["bom_ref"] == lgpl.bom_ref
    )
    assert len(lgpl_manifest["source"]["materials"]) == 2


def test_native_owner_resolution_and_graph_are_mandatory(
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, _artifacts = complete_bundle
    orphan = replace(value.native[0], owner_ref="pkg:pypi/absent@1")
    with pytest.raises(ComplianceError, match="no component owner"):
        validate_bundle_input(replace(value, native=(orphan, value.native[1])), policy)

    unresolved = replace(
        value.native[0],
        dependencies=(NativeDependency("missing.so", "/usr/lib/missing.so"),),
    )
    with pytest.raises(ComplianceError, match="not inventoried"):
        validate_bundle_input(
            replace(value, native=(unresolved, value.native[1])), policy
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("python_distributions", ("pytest==9.1.1",), "Python distributions"),
        ("debian_packages", ("libre2-dev==1.0",), "Debian packages"),
        ("executable_names", ("uv",), "executables"),
    ),
)
def test_runtime_development_tools_fail_closed(
    field: str,
    value: tuple[str, ...],
    message: str,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    bundle, _artifacts = complete_bundle
    runtime = replace(bundle.provenance.runtime, **{field: value})
    with pytest.raises(ComplianceError, match=message):
        validate_bundle_input(
            replace(bundle, provenance=replace(bundle.provenance, runtime=runtime)),
            policy,
        )


def test_incomplete_scan_fails_closed(
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, _artifacts = complete_bundle
    runtime = replace(value.provenance.runtime, native_scan_complete=False)
    with pytest.raises(ComplianceError, match="incomplete scan"):
        validate_bundle_input(
            replace(value, provenance=replace(value.provenance, runtime=runtime)),
            policy,
        )


def test_exact_package_version_mismatch_fails_closed(
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, _artifacts = complete_bundle
    runtime = replace(
        value.provenance.runtime,
        python_distributions=("lgpl-library==2.0.1", "mit-library==3.0.0"),
    )
    with pytest.raises(ComplianceError, match="exact runtime package inventories"):
        validate_bundle_input(
            replace(value, provenance=replace(value.provenance, runtime=runtime)),
            policy,
        )


def test_checksum_tamper_and_extra_file_fail_closed(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    first = ComplianceBundleBuilder(policy).build(value, artifacts, tmp_path / "tamper")
    (first / "THIRD_PARTY_NOTICES.md").write_bytes(b"tampered\n")
    with pytest.raises(ComplianceError, match="checksum differs"):
        ComplianceBundleVerifier(policy).verify(first)

    second = ComplianceBundleBuilder(policy).build(value, artifacts, tmp_path / "extra")
    (second / "unlisted.txt").write_text("extra")
    with pytest.raises(ComplianceError, match="checksummed file set differs"):
        ComplianceBundleVerifier(policy).verify(second)


def test_generated_bundle_paths_cannot_be_shadowed(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    root = value.components[0]
    shadowed = replace(root, license_path="PROVENANCE.json")
    updated = replace(value, components=(shadowed, *value.components[1:]))
    updated_artifacts = dict(artifacts)
    updated_artifacts.pop(root.license_path)
    updated_artifacts["PROVENANCE.json"] = b"not generated\n"
    with pytest.raises(ComplianceError, match="reserved"):
        ComplianceBundleBuilder(policy).build(
            updated, updated_artifacts, tmp_path / "shadowed"
        )


def test_rechecks_notices_after_attacker_rewrites_checksums(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    bundle = ComplianceBundleBuilder(policy).build(
        value, artifacts, tmp_path / "bundle"
    )
    (bundle / "THIRD_PARTY_NOTICES.md").write_text("plausible but incomplete\n")
    refresh_checksums(bundle)
    with pytest.raises(ComplianceError, match="notices differ"):
        ComplianceBundleVerifier(policy).verify(bundle)


def test_rechecks_source_obligation_after_attacker_rewrites_checksums(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    bundle = ComplianceBundleBuilder(policy).build(
        value, artifacts, tmp_path / "bundle"
    )
    manifest_path = bundle / "SOURCE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    root = next(
        component
        for component in manifest["components"]
        if component["bom_ref"] == value.provenance.root_component_ref
    )
    root["source_required"] = False
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    )
    refresh_checksums(bundle)
    with pytest.raises(ComplianceError, match="source obligation differs"):
        ComplianceBundleVerifier(policy).verify(bundle)


def test_rechecks_cyclonedx_edges_after_attacker_rewrites_checksums(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    bundle = ComplianceBundleBuilder(policy).build(
        value, artifacts, tmp_path / "bundle"
    )
    sbom_path = bundle / "sbom.cdx.json"
    sbom = json.loads(sbom_path.read_text())
    root_dependencies = next(
        record
        for record in sbom["dependencies"]
        if record["ref"] == value.provenance.root_component_ref
    )
    root_dependencies["dependsOn"] = []
    sbom_path.write_text(json.dumps(sbom, sort_keys=True, separators=(",", ":")) + "\n")
    refresh_checksums(bundle)
    with pytest.raises(ComplianceError, match="dependency edges differ"):
        ComplianceBundleVerifier(policy).verify(bundle)


def test_checksum_manifest_rejects_duplicate_and_unsorted_paths() -> None:
    digest = "a" * 64
    with pytest.raises(ComplianceError, match="duplicate"):
        parse_checksum_manifest(f"{digest}  a\n{digest}  a\n".encode())
    with pytest.raises(ComplianceError, match="strictly sorted"):
        parse_checksum_manifest(f"{digest}  b\n{digest}  a\n".encode())
    assert (
        build_checksum_manifest({"b": b"b", "a": b"a"})
        .decode()
        .splitlines()[0]
        .endswith("  a")
    )


def test_bundle_verifier_rejects_different_image(
    tmp_path: Path,
    policy: DistributionPolicy,
    complete_bundle: tuple[BundleInput, dict[str, bytes]],
) -> None:
    value, artifacts = complete_bundle
    bundle = ComplianceBundleBuilder(policy).build(
        value, artifacts, tmp_path / "bundle"
    )
    different = replace(value.provenance.image, image_id=f"sha256:{'9' * 64}")
    with pytest.raises(ComplianceError, match="not bound"):
        ComplianceBundleVerifier(policy).verify(bundle, expected_image=different)


class FakeRunner:
    def run(self, args: tuple[str, ...]) -> str:
        assert args[:3] == ("docker", "image", "inspect")
        return json.dumps(
            [
                {
                    "Architecture": "amd64",
                    "Config": {"Labels": {"label": "value"}},
                    "Id": IMAGE_ID,
                    "Os": "linux",
                    "RootFS": {"Layers": [ROOTFS_ID]},
                }
            ]
        )


def test_docker_inspector_binds_immutable_identity() -> None:
    identity = DockerImageInspector(FakeRunner()).inspect_identity("provider:test")
    assert identity.image_id == IMAGE_ID
    assert identity.platform == "linux/amd64"
    assert identity.rootfs_diff_ids == (ROOTFS_ID,)
