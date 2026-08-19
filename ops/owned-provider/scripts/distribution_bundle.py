"""Build and verify deterministic compliance bundles for one exact OCI image.

The bundle model is deliberately independent from Docker and the network.  An
image inspector and a bounded source retriever are provided as boundary
adapters; validation, decision tables, rendering, and checksum verification
remain pure and unit-testable.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import ipaddress
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import tomllib
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol, Sequence

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
LICENSE_EXPRESSION_RE = re.compile(r"^[A-Za-z0-9.+(): _-]+$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
FORMAT_NAME = "simplelogin-owned-provider-compliance"
NATIVE_REF_NAMESPACE = uuid.UUID("7a54254a-cfd6-55e9-8f3d-02efb8b50728")
MAX_BUNDLE_FILE_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024 * 1024
MAX_BUNDLE_FILES = 100_000
MAX_ARCHIVE_MEMBERS = 200_000
RUNTIME_PYTHON = "/opt/venv/bin/python"
GENERATED_BUNDLE_PATHS = frozenset(
    {
        "PROVENANCE.json",
        "SHA256SUMS",
        "SOURCE_MANIFEST.json",
        "THIRD_PARTY_NOTICES.md",
        "relink/MATERIALS.json",
        "sbom.cdx.json",
    }
)


class ComplianceError(RuntimeError):
    """A fail-closed compliance validation error."""


def canonical_json(value: object) -> bytes:
    """Return a stable UTF-8 JSON representation with exactly one final LF."""

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalize_python_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def read_bounded_file(
    path: Path, *, maximum_bytes: int = MAX_BUNDLE_FILE_BYTES
) -> bytes:
    size = path.stat().st_size
    if size > maximum_bytes:
        raise ComplianceError(f"file exceeds its byte limit: {path}")
    payload = path.read_bytes()
    if len(payload) > maximum_bytes:
        raise ComplianceError(f"file grew beyond its byte limit: {path}")
    return payload


def validate_relative_path(value: str) -> str:
    """Validate an unambiguous, portable bundle path and return it unchanged."""

    if (
        not value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ComplianceError(f"unsafe bundle path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix():
        raise ComplianceError(f"bundle path is not canonical: {value!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ComplianceError(f"bundle path escapes its root: {value!r}")
    return value


def safe_component_filename(value: str) -> str:
    safe = SAFE_NAME_RE.sub("-", value).strip(".-")
    if not safe:
        raise ComplianceError(f"component name has no safe filename: {value!r}")
    return safe


def validate_digest(value: str, *, field_name: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise ComplianceError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def validate_url(value: str, *, field_name: str) -> str:
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise ComplianceError(f"{field_name} contains whitespace or control characters")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username:
        raise ComplianceError(f"{field_name} must be an unauthenticated HTTPS URL")
    if parsed.query or parsed.fragment:
        raise ComplianceError(f"{field_name} must not contain a query or fragment")
    hostname = parsed.hostname or ""
    if hostname.lower() == "localhost" or hostname.lower().endswith(".local"):
        raise ComplianceError(f"{field_name} must identify a public source host")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ComplianceError(f"{field_name} must not use a private IP address")
    return value


def _archive_member_path(
    name: str, *, archive: str, allow_posix_backslash: bool = False
) -> PurePosixPath:
    if ("\\" in name and not allow_posix_backslash) or any(
        ord(character) < 32 or ord(character) == 127 for character in name
    ):
        raise ComplianceError(f"unsafe path in {archive}: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ComplianceError(f"archive member escapes its root in {archive}: {name}")
    return path


def validate_source_archive(path: str, payload: bytes) -> None:
    """Reject unsafe or unreadable source materials before they enter a bundle."""

    lower = path.lower()
    if not payload:
        raise ComplianceError(f"source material is empty: {path}")
    if len(payload) > MAX_BUNDLE_FILE_BYTES:
        raise ComplianceError(f"source material exceeds its byte limit: {path}")
    if lower.endswith(".dsc"):
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ComplianceError(
                f"invalid Debian source control file {path}: {error}"
            ) from error
        required_fields = ("Format", "Source", "Files", "Checksums-Sha256")
        missing = [
            field
            for field in required_fields
            if re.search(rf"(?m)^{re.escape(field)}:\s*\S", text) is None
        ]
        if missing:
            raise ComplianceError(
                f"Debian source control file lacks required fields {missing}: {path}"
            )
        if (
            "-----BEGIN PGP SIGNED MESSAGE-----" not in text
            or "-----BEGIN PGP SIGNATURE-----" not in text
            or "-----END PGP SIGNATURE-----" not in text
        ):
            raise ComplianceError(
                f"Debian source control file is not clear-signed: {path}"
            )
        return
    if lower.endswith(".diff.gz"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(payload)) as archive:
                patch = archive.read(MAX_BUNDLE_FILE_BYTES + 1)
        except (gzip.BadGzipFile, OSError, EOFError) as error:
            raise ComplianceError(
                f"invalid Debian source diff {path}: {error}"
            ) from error
        if len(patch) > MAX_BUNDLE_FILE_BYTES:
            raise ComplianceError(f"Debian source diff exceeds its byte limit: {path}")
        if not patch.strip() or b"--- " not in patch or b"+++ " not in patch:
            raise ComplianceError(f"Debian source diff has no unified patch: {path}")
        return
    if lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
                member_count = 0
                for member in archive:
                    member_count += 1
                    if member_count > MAX_ARCHIVE_MEMBERS:
                        raise ComplianceError(
                            f"source archive has too many members: {path}"
                        )
                    member_path = _archive_member_path(
                        member.name, archive=path, allow_posix_backslash=True
                    )
                    if member.issym() or member.islnk():
                        target = PurePosixPath(member.linkname)
                        if target.is_absolute():
                            raise ComplianceError(
                                f"absolute archive link target in {path}: {member.linkname}"
                            )
                        combined = member_path.parent.joinpath(target)
                        depth = 0
                        for part in combined.parts:
                            if part == "..":
                                depth -= 1
                            elif part not in {"", "."}:
                                depth += 1
                            if depth < 0:
                                raise ComplianceError(
                                    f"archive link escapes its root in {path}: "
                                    f"{member.name} -> {member.linkname}"
                                )
                if not member_count:
                    raise ComplianceError(f"source archive is empty: {path}")
        except (tarfile.TarError, OSError) as error:
            raise ComplianceError(f"invalid source archive {path}: {error}") from error
        return
    if lower.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                members = archive.infolist()
                if not members:
                    raise ComplianceError(f"source archive is empty: {path}")
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise ComplianceError(
                        f"source archive has too many members: {path}"
                    )
                for member in members:
                    _archive_member_path(member.filename, archive=path)
                    mode = member.external_attr >> 16
                    if (mode & 0o170000) == 0o120000:
                        target = archive.read(member).decode(errors="strict")
                        target_path = PurePosixPath(target)
                        if target_path.is_absolute() or ".." in target_path.parts:
                            raise ComplianceError(
                                f"unsafe zip link target in {path}: {member.filename}"
                            )
        except (UnicodeDecodeError, zipfile.BadZipFile, OSError) as error:
            raise ComplianceError(f"invalid source archive {path}: {error}") from error
        return
    raise ComplianceError(f"source material is not a supported archive: {path}")


def license_families(expression: str) -> frozenset[str]:
    upper = expression.upper()
    families: set[str] = set()
    if "LGPL" in upper:
        families.add("LGPL")
    if "AGPL" in upper:
        families.add("AGPL")
    scrubbed = upper.replace("LGPL", "").replace("AGPL", "")
    if "GPL" in scrubbed:
        families.add("GPL")
    for family in ("MPL", "EPL", "CDDL"):
        if family in upper:
            families.add(family)
    return frozenset(families)


@dataclass(frozen=True)
class DistributionPolicy:
    format_version: int
    bundle_format: str
    bundle_format_version: int
    cyclonedx_spec_version: str
    fork_source_url: str
    upstream_source_url: str
    license_expression: str
    source_license_families: frozenset[str]
    relink_license_families: frozenset[str]
    allowed_license_ids: frozenset[str]
    allowed_license_exceptions: frozenset[str]
    allowed_license_refs: frozenset[str]
    relink_material_kinds: Mapping[str, frozenset[str]]
    forbidden_python_distributions: frozenset[str]
    forbidden_executables: frozenset[str]
    forbidden_debian_packages: frozenset[str]
    forbidden_debian_suffixes: tuple[str, ...]
    external_images: Mapping[str, str]

    @classmethod
    def load(cls, path: Path) -> "DistributionPolicy":
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        obligations = raw["obligations"]
        runtime = raw["runtime"]
        provenance = raw["provenance"]
        policy = cls(
            format_version=int(raw["format_version"]),
            bundle_format=str(raw["bundle_format"]),
            bundle_format_version=int(raw["bundle_format_version"]),
            cyclonedx_spec_version=str(raw["cyclonedx_spec_version"]),
            fork_source_url=str(provenance["fork_source_url"]),
            upstream_source_url=str(provenance["upstream_source_url"]),
            license_expression=str(provenance["license_expression"]),
            source_license_families=frozenset(obligations["source_license_families"]),
            relink_license_families=frozenset(obligations["relink_license_families"]),
            allowed_license_ids=frozenset(obligations["allowed_license_ids"]),
            allowed_license_exceptions=frozenset(
                obligations["allowed_license_exceptions"]
            ),
            allowed_license_refs=frozenset(obligations["allowed_license_refs"]),
            relink_material_kinds={
                linkage: frozenset(obligations[f"{linkage}_relink_material_kinds"])
                for linkage in ("static", "dynamic", "interpreted")
            },
            forbidden_python_distributions=frozenset(
                name.lower() for name in runtime["forbidden_python_distributions"]
            ),
            forbidden_executables=frozenset(runtime["forbidden_executables"]),
            forbidden_debian_packages=frozenset(runtime["forbidden_debian_packages"]),
            forbidden_debian_suffixes=tuple(runtime["forbidden_debian_suffixes"]),
            external_images=dict(raw["external_images"]),
        )
        if policy.format_version != 1 or policy.bundle_format != FORMAT_NAME:
            raise ComplianceError("unsupported distribution policy format")
        validate_url(policy.fork_source_url, field_name="fork source URL")
        validate_url(policy.upstream_source_url, field_name="upstream source URL")
        return policy

    def requires_source(self, expression: str) -> bool:
        return bool(license_families(expression) & self.source_license_families)

    def requires_relink(self, expression: str) -> bool:
        return bool(license_families(expression) & self.relink_license_families)


@dataclass(frozen=True)
class SourceMaterial:
    path: str
    download_url: str
    sha256: str


@dataclass(frozen=True)
class ComponentRecord:
    bom_ref: str
    name: str
    version: str
    component_type: str
    ecosystem: str
    purl: str
    license_expression: str
    license_path: str
    source_url: str
    source_materials: tuple[SourceMaterial, ...] = ()
    installed_sha256: str | None = None
    copyright_notice: str = ""
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class NativeDependency:
    soname: str
    resolved_path: str


@dataclass(frozen=True)
class NativeRecord:
    path: str
    sha256: str
    owner_ref: str
    dependencies: tuple[NativeDependency, ...] = ()

    @property
    def bom_ref(self) -> str:
        return f"native:{uuid.uuid5(NATIVE_REF_NAMESPACE, self.path)}"


@dataclass(frozen=True)
class ObservedNativeRecord:
    path: str
    sha256: str
    dependencies: tuple[NativeDependency, ...] = ()


@dataclass(frozen=True)
class RelinkRecord:
    component_ref: str
    linkage: str
    consumers: tuple[str, ...]
    instructions_path: str
    material_paths: tuple[str, ...]
    material_kinds: tuple[str, ...]


@dataclass(frozen=True)
class ImageIdentity:
    image_reference: str
    image_id: str
    platform: str
    rootfs_diff_ids: tuple[str, ...]
    labels: Mapping[str, str]


@dataclass(frozen=True)
class RuntimeInventory:
    python_distributions: tuple[str, ...]
    debian_packages: tuple[str, ...]
    npm_packages: tuple[str, ...]
    executable_names: tuple[str, ...]
    python_scan_complete: bool
    debian_scan_complete: bool
    npm_scan_complete: bool
    executable_scan_complete: bool
    native_scan_complete: bool


@dataclass(frozen=True)
class ProvenanceRecord:
    repository_revision: str
    upstream_revision: str
    image: ImageIdentity
    root_component_ref: str
    runtime: RuntimeInventory


@dataclass(frozen=True)
class BundleInput:
    provenance: ProvenanceRecord
    components: tuple[ComponentRecord, ...]
    native: tuple[NativeRecord, ...]
    relinking: tuple[RelinkRecord, ...]


def validate_license(expression: str, policy: DistributionPolicy) -> None:
    if (
        not expression
        or expression.upper() in {"UNKNOWN", "NOASSERTION", "NONE"}
        or not LICENSE_EXPRESSION_RE.fullmatch(expression)
    ):
        raise ComplianceError(f"invalid or unknown license expression: {expression!r}")
    for reference in re.findall(r"LicenseRef-[A-Za-z0-9.-]+", expression):
        if reference not in policy.allowed_license_refs:
            raise ComplianceError(f"unapproved license reference: {reference}")
    tokens = set(re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression))
    identifiers = tokens - {"AND", "OR", "WITH"}
    unknown = sorted(
        identifier
        for identifier in identifiers
        if identifier not in policy.allowed_license_ids
        and identifier not in policy.allowed_license_exceptions
        and identifier not in policy.allowed_license_refs
    )
    if unknown:
        raise ComplianceError(f"unapproved SPDX license identifiers: {unknown}")


def validate_runtime_inventory(
    runtime: RuntimeInventory, policy: DistributionPolicy
) -> None:
    if not all(
        (
            runtime.python_scan_complete,
            runtime.debian_scan_complete,
            runtime.npm_scan_complete,
            runtime.executable_scan_complete,
            runtime.native_scan_complete,
        )
    ):
        raise ComplianceError("runtime inventory contains an incomplete scan")
    python_names = []
    for distribution in runtime.python_distributions:
        name, separator, version = distribution.partition("==")
        if not separator or not name or not version:
            raise ComplianceError(
                "Python inventory must contain exact name==version records"
            )
        normalized = normalize_python_name(name)
        if name != normalized:
            raise ComplianceError("Python inventory names must use canonical spelling")
        python_names.append(normalized)
    debian_names = []
    for package in runtime.debian_packages:
        name, separator, version = package.partition("==")
        if not separator or not name or not version:
            raise ComplianceError(
                "Debian inventory must contain exact name==version records"
            )
        debian_names.append(name)
    for package in runtime.npm_packages:
        name, separator, version = package.rpartition("@")
        if not separator or not name or not version:
            raise ComplianceError(
                "npm inventory must contain exact name@version records"
            )
    forbidden_python = sorted(set(python_names) & policy.forbidden_python_distributions)
    if forbidden_python:
        raise ComplianceError(
            f"development Python distributions shipped: {forbidden_python}"
        )
    forbidden_executables = sorted(
        set(runtime.executable_names) & policy.forbidden_executables
    )
    if forbidden_executables:
        raise ComplianceError(
            f"development executables shipped: {forbidden_executables}"
        )
    forbidden_debian = sorted(
        package
        for package in debian_names
        if package in policy.forbidden_debian_packages
        or package.endswith(policy.forbidden_debian_suffixes)
    )
    if forbidden_debian:
        raise ComplianceError(
            f"development Debian packages shipped: {forbidden_debian}"
        )


def validate_bundle_input(value: BundleInput, policy: DistributionPolicy) -> None:
    provenance = value.provenance
    if not REVISION_RE.fullmatch(provenance.repository_revision):
        raise ComplianceError("fork revision must be an exact 40-character Git SHA")
    if not REVISION_RE.fullmatch(provenance.upstream_revision):
        raise ComplianceError("upstream revision must be an exact 40-character Git SHA")
    if not IMAGE_SHA256_RE.fullmatch(provenance.image.image_id):
        raise ComplianceError("image ID must be a sha256 digest")
    if provenance.image.platform != "linux/amd64":
        raise ComplianceError("production compliance bundle must target linux/amd64")
    if not provenance.image.rootfs_diff_ids or any(
        not IMAGE_SHA256_RE.fullmatch(digest)
        for digest in provenance.image.rootfs_diff_ids
    ):
        raise ComplianceError("image rootfs diff IDs are missing or invalid")
    validate_runtime_inventory(provenance.runtime, policy)

    expected_labels = {
        "org.opencontainers.image.licenses": policy.license_expression,
        "org.opencontainers.image.revision": provenance.repository_revision,
        "org.opencontainers.image.source": policy.fork_source_url,
        "org.opencontainers.image.upstream.revision": provenance.upstream_revision,
    }
    actual_labels = {key: provenance.image.labels.get(key) for key in expected_labels}
    if actual_labels != expected_labels:
        raise ComplianceError(
            f"image provenance labels differ: {actual_labels} != {expected_labels}"
        )

    if not value.components:
        raise ComplianceError("component inventory is empty")
    component_map = {component.bom_ref: component for component in value.components}
    if len(component_map) != len(value.components):
        raise ComplianceError("component bom-ref values are not unique")
    if provenance.root_component_ref not in component_map:
        raise ComplianceError("root component is absent from component inventory")
    root = component_map[provenance.root_component_ref]
    if root.license_expression != policy.license_expression:
        raise ComplianceError("root component does not carry the project license")
    if root.source_url != policy.fork_source_url:
        raise ComplianceError("root component does not point to the exact fork source")
    expected_fork_download = (
        f"{policy.fork_source_url}/archive/{provenance.repository_revision}.tar.gz"
    )
    if (
        len(root.source_materials) != 1
        or root.source_materials[0].download_url != expected_fork_download
    ):
        raise ComplianceError(
            "root source archive URL does not contain the exact fork SHA"
        )

    for component in value.components:
        if not component.name or not component.version or not component.bom_ref:
            raise ComplianceError("component identity is incomplete")
        if not component.purl.startswith("pkg:"):
            raise ComplianceError(f"component lacks a package URL: {component.bom_ref}")
        validate_license(component.license_expression, policy)
        validate_url(
            component.source_url, field_name=f"source URL for {component.bom_ref}"
        )
        validate_relative_path(component.license_path)
        if component.installed_sha256 is not None:
            validate_digest(
                component.installed_sha256,
                field_name=f"installed digest for {component.bom_ref}",
            )
        unknown_dependencies = sorted(
            set(component.dependencies) - component_map.keys()
        )
        if unknown_dependencies:
            raise ComplianceError(
                f"component {component.bom_ref} has unknown dependencies: "
                f"{unknown_dependencies}"
            )
        if policy.requires_source(component.license_expression):
            if not component.source_materials:
                raise ComplianceError(
                    f"copyleft component lacks exact source material: {component.bom_ref}"
                )
        elif component.source_materials:
            raise ComplianceError(
                f"non-copyleft component has bundled source material: {component.bom_ref}"
            )
        source_paths: set[str] = set()
        for material in sorted(component.source_materials, key=lambda item: item.path):
            validate_url(
                material.download_url,
                field_name=f"source download URL for {component.bom_ref}",
            )
            validate_digest(
                material.sha256,
                field_name=f"source digest for {component.bom_ref}",
            )
            validate_relative_path(material.path)
            if material.path in source_paths:
                raise ComplianceError(
                    f"component source path is duplicated: {component.bom_ref}"
                )
            source_paths.add(material.path)

    component_python = {
        f"{normalize_python_name(component.name)}=={component.version}"
        for component in value.components
        if component.ecosystem == "pypi"
    }
    component_debian = {
        f"{component.name}=={component.version}"
        for component in value.components
        if component.ecosystem == "deb"
    }
    component_npm = {
        f"{component.name}@{component.version}"
        for component in value.components
        if component.ecosystem == "npm"
    }
    if (
        component_python != set(provenance.runtime.python_distributions)
        or component_debian != set(provenance.runtime.debian_packages)
        or component_npm != set(provenance.runtime.npm_packages)
    ):
        raise ComplianceError(
            "component inventory differs from the exact runtime package inventories"
        )

    native_paths = {record.path: record for record in value.native}
    if len(native_paths) != len(value.native):
        raise ComplianceError("native artifact paths are not unique")
    for record in value.native:
        validate_relative_path(record.path.removeprefix("/"))
        validate_digest(record.sha256, field_name=f"native digest for {record.path}")
        if PurePosixPath(record.path).name in policy.forbidden_executables:
            raise ComplianceError(
                f"development native executable shipped: {record.path}"
            )
        if record.owner_ref not in component_map:
            raise ComplianceError(
                f"native artifact has no component owner: {record.path}"
            )
        for dependency in record.dependencies:
            if not dependency.soname or not dependency.resolved_path:
                raise ComplianceError(f"native dependency is unresolved: {record.path}")
            if dependency.resolved_path not in native_paths:
                raise ComplianceError(
                    f"native dependency target is not inventoried: {record.path} -> "
                    f"{dependency.resolved_path}"
                )

    relink_map = {record.component_ref: record for record in value.relinking}
    if len(relink_map) != len(value.relinking):
        raise ComplianceError("relinking component records are not unique")
    required_relink = {
        component.bom_ref
        for component in value.components
        if policy.requires_relink(component.license_expression)
    }
    missing_relink = sorted(required_relink - relink_map.keys())
    extra_relink = sorted(relink_map.keys() - required_relink)
    if missing_relink or extra_relink:
        raise ComplianceError(
            f"relinking coverage differs: missing={missing_relink}, extra={extra_relink}"
        )
    for record in value.relinking:
        if record.linkage not in policy.relink_material_kinds:
            raise ComplianceError(f"unsupported relinking mode: {record.linkage}")
        if not record.consumers:
            raise ComplianceError(
                f"relinking consumers are absent: {record.component_ref}"
            )
        for consumer in record.consumers:
            if not consumer.startswith("/"):
                raise ComplianceError(
                    f"relinking consumer is not an absolute runtime path: {consumer}"
                )
            validate_relative_path(consumer.removeprefix("/"))
        if (
            record.linkage in {"dynamic", "static"}
            and not set(record.consumers) <= native_paths.keys()
        ):
            raise ComplianceError(
                f"native relinking consumer is not inventoried: {record.component_ref}"
            )
        validate_relative_path(record.instructions_path)
        for path in record.material_paths:
            validate_relative_path(path)
        if len(record.material_paths) != len(record.material_kinds):
            raise ComplianceError(
                f"relinking material metadata differs: {record.component_ref}"
            )
        required_kinds = policy.relink_material_kinds[record.linkage]
        missing_kinds = sorted(required_kinds - set(record.material_kinds))
        if missing_kinds:
            raise ComplianceError(
                f"relinking materials incomplete for {record.component_ref}: {missing_kinds}"
            )
        material_pairs = set(
            zip(record.material_paths, record.material_kinds, strict=True)
        )
        component = component_map[record.component_ref]
        if (record.instructions_path, "instructions") not in material_pairs:
            raise ComplianceError(
                f"relinking instructions are not declared as material: {record.component_ref}"
            )
        component_source_paths = {
            material.path for material in component.source_materials
        }
        declared_source_paths = {
            path for path, kind in material_pairs if kind == "source"
        }
        if component_source_paths != declared_source_paths:
            raise ComplianceError(
                f"relinking source differs from corresponding source: {record.component_ref}"
            )


def expected_artifact_paths(value: BundleInput) -> frozenset[str]:
    paths: set[str] = set()
    for component in value.components:
        paths.add(component.license_path)
        paths.update(material.path for material in component.source_materials)
    for record in value.relinking:
        paths.add(record.instructions_path)
        paths.update(record.material_paths)
    return frozenset(paths)


def render_component_notices(components: Sequence[ComponentRecord]) -> bytes:
    lines = [
        "# Third-party notices",
        "",
        "This inventory describes bytes present in the exact production OCI artifact.",
        "",
    ]
    for component in sorted(components, key=lambda item: item.bom_ref):
        lines.extend(
            [
                f"## {component.name} {component.version}",
                "",
                f"- Package URL: `{component.purl}`",
                f"- License: `{component.license_expression}`",
                f"- License text: `{component.license_path}`",
                f"- Source: {component.source_url}",
            ]
        )
        for material in sorted(component.source_materials, key=lambda item: item.path):
            lines.append(f"- Bundled corresponding source: `{material.path}`")
        if component.copyright_notice:
            notice = " ".join(component.copyright_notice.splitlines()).strip()
            lines.append(f"- Copyright: {notice}")
        lines.append("")
    return ("\n".join(lines).rstrip() + "\n").encode()


def render_notices(value: BundleInput) -> bytes:
    return render_component_notices(value.components)


def render_provenance(value: BundleInput, policy: DistributionPolicy) -> bytes:
    provenance = value.provenance
    return canonical_json(
        {
            "external_images": dict(sorted(policy.external_images.items())),
            "fork": {
                "revision": provenance.repository_revision,
                "source": policy.fork_source_url,
            },
            "format": policy.bundle_format,
            "format_version": policy.bundle_format_version,
            "image": {
                "id": provenance.image.image_id,
                "labels": dict(sorted(provenance.image.labels.items())),
                "platform": provenance.image.platform,
                "reference": provenance.image.image_reference,
                "rootfs_diff_ids": list(provenance.image.rootfs_diff_ids),
            },
            "root_component_ref": provenance.root_component_ref,
            "runtime_inventory": {
                "debian_packages": sorted(provenance.runtime.debian_packages),
                "executable_names": sorted(provenance.runtime.executable_names),
                "npm_packages": sorted(provenance.runtime.npm_packages),
                "python_distributions": sorted(provenance.runtime.python_distributions),
                "scans_complete": {
                    "debian": provenance.runtime.debian_scan_complete,
                    "executables": provenance.runtime.executable_scan_complete,
                    "native": provenance.runtime.native_scan_complete,
                    "npm": provenance.runtime.npm_scan_complete,
                    "python": provenance.runtime.python_scan_complete,
                },
            },
            "upstream": {
                "revision": provenance.upstream_revision,
                "source": policy.upstream_source_url,
            },
        }
    )


def render_source_manifest(value: BundleInput, policy: DistributionPolicy) -> bytes:
    components = []
    for component in sorted(value.components, key=lambda item: item.bom_ref):
        components.append(
            {
                "bom_ref": component.bom_ref,
                "copyright_notice": component.copyright_notice,
                "dependencies": sorted(component.dependencies),
                "license": component.license_expression,
                "license_path": component.license_path,
                "name": component.name,
                "purl": component.purl,
                "source": {
                    "materials": [
                        {
                            "archive_path": material.path,
                            "download_url": material.download_url,
                            "sha256": material.sha256,
                        }
                        for material in sorted(
                            component.source_materials, key=lambda item: item.path
                        )
                    ],
                    "url": component.source_url,
                },
                "source_required": policy.requires_source(component.license_expression),
                "version": component.version,
            }
        )
    return canonical_json(
        {
            "components": components,
            "format": "simplelogin-owned-provider-source-manifest",
            "format_version": 1,
        }
    )


def render_relink_manifest(value: BundleInput) -> bytes:
    return canonical_json(
        {
            "format": "simplelogin-owned-provider-relink-manifest",
            "format_version": 1,
            "records": [
                {
                    "component_ref": record.component_ref,
                    "consumers": sorted(record.consumers),
                    "instructions_path": record.instructions_path,
                    "linkage": record.linkage,
                    "materials": [
                        {"kind": kind, "path": path}
                        for path, kind in sorted(
                            zip(
                                record.material_paths,
                                record.material_kinds,
                                strict=True,
                            )
                        )
                    ],
                }
                for record in sorted(
                    value.relinking, key=lambda item: item.component_ref
                )
            ],
        }
    )


def _component_cyclonedx(component: ComponentRecord) -> dict[str, Any]:
    rendered: dict[str, Any] = {
        "bom-ref": component.bom_ref,
        "externalReferences": [{"type": "distribution", "url": component.source_url}],
        "licenses": [{"expression": component.license_expression}],
        "name": component.name,
        "properties": [
            {"name": "owned-provider:ecosystem", "value": component.ecosystem},
            {"name": "owned-provider:license-path", "value": component.license_path},
        ],
        "purl": component.purl,
        "type": component.component_type,
        "version": component.version,
    }
    if component.installed_sha256:
        rendered["hashes"] = [{"alg": "SHA-256", "content": component.installed_sha256}]
    if component.source_materials:
        rendered["properties"].extend(
            [
                {
                    "name": "owned-provider:source-materials",
                    "value": json.dumps(
                        [
                            {
                                "archive_path": material.path,
                                "download_url": material.download_url,
                                "sha256": material.sha256,
                            }
                            for material in sorted(
                                component.source_materials, key=lambda item: item.path
                            )
                        ],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            ]
        )
    return rendered


def render_cyclonedx(value: BundleInput, policy: DistributionPolicy) -> bytes:
    component_map = {component.bom_ref: component for component in value.components}
    root_ref = value.provenance.root_component_ref
    root = component_map[root_ref]
    native_components = [
        {
            "bom-ref": record.bom_ref,
            "hashes": [{"alg": "SHA-256", "content": record.sha256}],
            "name": PurePosixPath(record.path).name,
            "properties": [
                {"name": "owned-provider:native-owner", "value": record.owner_ref},
                {"name": "owned-provider:native-path", "value": record.path},
                {
                    "name": "owned-provider:native-needed",
                    "value": json.dumps(
                        [
                            {
                                "resolved_path": dependency.resolved_path,
                                "soname": dependency.soname,
                            }
                            for dependency in sorted(
                                record.dependencies,
                                key=lambda item: (item.soname, item.resolved_path),
                            )
                        ],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            ],
            "type": "file",
            "version": record.sha256,
        }
        for record in sorted(value.native, key=lambda item: item.path)
    ]
    dependencies: list[dict[str, Any]] = []
    for component in sorted(value.components, key=lambda item: item.bom_ref):
        owned_native = sorted(
            record.bom_ref
            for record in value.native
            if record.owner_ref == component.bom_ref
        )
        dependencies.append(
            {
                "dependsOn": sorted(set(component.dependencies) | set(owned_native)),
                "ref": component.bom_ref,
            }
        )
    native_by_path = {record.path: record for record in value.native}
    for record in sorted(value.native, key=lambda item: item.path):
        dependencies.append(
            {
                "dependsOn": sorted(
                    native_by_path[dependency.resolved_path].bom_ref
                    for dependency in record.dependencies
                ),
                "ref": record.bom_ref,
            }
        )
    document = {
        "bomFormat": "CycloneDX",
        "components": [
            _component_cyclonedx(component)
            for component in sorted(value.components, key=lambda item: item.bom_ref)
            if component.bom_ref != root_ref
        ]
        + native_components,
        "dependencies": dependencies,
        "metadata": {
            "component": _component_cyclonedx(root),
            "properties": [
                {
                    "name": "owned-provider:image-id",
                    "value": value.provenance.image.image_id,
                },
                {
                    "name": "owned-provider:repository-revision",
                    "value": value.provenance.repository_revision,
                },
                {
                    "name": "owned-provider:upstream-revision",
                    "value": value.provenance.upstream_revision,
                },
            ],
        },
        "serialNumber": f"urn:uuid:{uuid.uuid5(NATIVE_REF_NAMESPACE, value.provenance.image.image_id)}",
        "specVersion": policy.cyclonedx_spec_version,
        "version": 1,
    }
    return canonical_json(document)


def build_checksum_manifest(files: Mapping[str, bytes]) -> bytes:
    return "".join(
        f"{sha256_bytes(payload)}  {path}\n" for path, payload in sorted(files.items())
    ).encode()


class ComplianceBundleBuilder:
    """Own the temporary output tree and publish it atomically when complete."""

    def __init__(self, policy: DistributionPolicy) -> None:
        self.policy = policy

    def build(
        self,
        value: BundleInput,
        artifacts: Mapping[str, bytes],
        destination: Path,
    ) -> Path:
        validate_bundle_input(value, self.policy)
        if destination.exists():
            raise ComplianceError(f"bundle destination already exists: {destination}")
        normalized_artifacts = {
            validate_relative_path(path): data for path, data in artifacts.items()
        }
        if len(normalized_artifacts) != len(artifacts):
            raise ComplianceError("artifact bundle paths are not unique")
        reserved = sorted(normalized_artifacts.keys() & GENERATED_BUNDLE_PATHS)
        if reserved:
            raise ComplianceError(
                f"artifact paths are reserved for generated files: {reserved}"
            )
        if (
            len(normalized_artifacts) > MAX_BUNDLE_FILES
            or sum(len(payload) for payload in normalized_artifacts.values())
            > MAX_BUNDLE_BYTES
            or any(
                len(payload) > MAX_BUNDLE_FILE_BYTES
                for payload in normalized_artifacts.values()
            )
        ):
            raise ComplianceError("compliance artifacts exceed their resource limits")
        expected = expected_artifact_paths(value)
        actual = frozenset(normalized_artifacts)
        if actual != expected:
            raise ComplianceError(
                f"artifact set differs: missing={sorted(expected - actual)}, "
                f"extra={sorted(actual - expected)}"
            )
        for component in value.components:
            license_payload = normalized_artifacts[component.license_path]
            if not license_payload.strip():
                raise ComplianceError(
                    f"license text is empty: {component.license_path}"
                )
            for material in component.source_materials:
                source_payload = normalized_artifacts[material.path]
                if sha256_bytes(source_payload) != material.sha256:
                    raise ComplianceError(
                        f"source digest differs for {component.bom_ref}"
                    )
                validate_source_archive(material.path, source_payload)
        for record in value.relinking:
            if not normalized_artifacts[record.instructions_path].strip():
                raise ComplianceError(
                    f"relinking instructions are empty: {record.instructions_path}"
                )

        generated = dict(normalized_artifacts)
        generated["PROVENANCE.json"] = render_provenance(value, self.policy)
        generated["SOURCE_MANIFEST.json"] = render_source_manifest(value, self.policy)
        generated["THIRD_PARTY_NOTICES.md"] = render_notices(value)
        generated["relink/MATERIALS.json"] = render_relink_manifest(value)
        generated["sbom.cdx.json"] = render_cyclonedx(value, self.policy)
        generated["SHA256SUMS"] = build_checksum_manifest(generated)

        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
        )
        try:
            for relative, payload in sorted(generated.items()):
                target = temporary / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                target.chmod(0o644)
            temporary.rename(destination)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return destination


def parse_checksum_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ComplianceError("SHA256SUMS is not UTF-8") from error
    checksums: dict[str, str] = {}
    previous = ""
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise ComplianceError(f"malformed SHA256SUMS line: {line!r}")
        digest, path = line[:64], line[66:]
        validate_digest(digest, field_name="SHA256SUMS digest")
        validate_relative_path(path)
        if path == "SHA256SUMS":
            raise ComplianceError("SHA256SUMS must not checksum itself")
        if path in checksums:
            raise ComplianceError(f"duplicate SHA256SUMS path: {path}")
        if previous and path <= previous:
            raise ComplianceError("SHA256SUMS paths are not strictly sorted")
        previous = path
        checksums[path] = digest
    if not checksums:
        raise ComplianceError("SHA256SUMS is empty")
    return checksums


def _read_bundle_files(bundle: Path) -> dict[str, bytes]:
    if not bundle.is_dir() or bundle.is_symlink():
        raise ComplianceError(f"bundle is not a real directory: {bundle}")
    files: dict[str, bytes] = {}
    total_size = 0
    for path in sorted(bundle.rglob("*")):
        if path.is_symlink():
            raise ComplianceError(f"bundle contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ComplianceError(f"bundle contains a non-regular file: {path}")
        relative = path.relative_to(bundle).as_posix()
        validate_relative_path(relative)
        payload = read_bounded_file(path)
        total_size += len(payload)
        if len(files) >= MAX_BUNDLE_FILES or total_size > MAX_BUNDLE_BYTES:
            raise ComplianceError("bundle exceeds its file-count or total-byte limit")
        files[relative] = payload
    return files


class ComplianceBundleVerifier:
    def __init__(self, policy: DistributionPolicy) -> None:
        self.policy = policy

    def verify(
        self,
        bundle: Path,
        *,
        expected_image: ImageIdentity | None = None,
        expected_runtime: RuntimeInventory | None = None,
        expected_native: Sequence[ObservedNativeRecord] | None = None,
        expected_repository_revision: str | None = None,
        expected_upstream_revision: str | None = None,
    ) -> dict[str, Any]:
        files = _read_bundle_files(bundle)
        if "SHA256SUMS" not in files:
            raise ComplianceError("bundle lacks SHA256SUMS")
        checksums = parse_checksum_manifest(files["SHA256SUMS"])
        actual_paths = set(files) - {"SHA256SUMS"}
        if actual_paths != checksums.keys():
            raise ComplianceError(
                f"checksummed file set differs: missing={sorted(checksums.keys() - actual_paths)}, "
                f"extra={sorted(actual_paths - checksums.keys())}"
            )
        for path, expected in checksums.items():
            actual = sha256_bytes(files[path])
            if actual != expected:
                raise ComplianceError(
                    f"bundle checksum differs for {path}: {actual} != {expected}"
                )
        required = {
            "PROVENANCE.json",
            "SOURCE_MANIFEST.json",
            "THIRD_PARTY_NOTICES.md",
            "relink/MATERIALS.json",
            "sbom.cdx.json",
        }
        missing = sorted(required - files.keys())
        if missing:
            raise ComplianceError(f"bundle lacks required generated files: {missing}")
        try:
            provenance = json.loads(files["PROVENANCE.json"])
            source_manifest = json.loads(files["SOURCE_MANIFEST.json"])
            relink_manifest = json.loads(files["relink/MATERIALS.json"])
            sbom = json.loads(files["sbom.cdx.json"])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ComplianceError(f"bundle JSON is invalid: {error}") from error
        if canonical_json(provenance) != files["PROVENANCE.json"]:
            raise ComplianceError("PROVENANCE.json is not canonical")
        if canonical_json(source_manifest) != files["SOURCE_MANIFEST.json"]:
            raise ComplianceError("SOURCE_MANIFEST.json is not canonical")
        if canonical_json(relink_manifest) != files["relink/MATERIALS.json"]:
            raise ComplianceError("relink/MATERIALS.json is not canonical")
        if canonical_json(sbom) != files["sbom.cdx.json"]:
            raise ComplianceError("sbom.cdx.json is not canonical")
        if provenance.get("format") != self.policy.bundle_format:
            raise ComplianceError("provenance format differs from policy")
        if (
            sbom.get("bomFormat") != "CycloneDX"
            or sbom.get("specVersion") != self.policy.cyclonedx_spec_version
        ):
            raise ComplianceError("CycloneDX format or version differs from policy")
        if (
            source_manifest.get("format")
            != "simplelogin-owned-provider-source-manifest"
        ):
            raise ComplianceError("source manifest format is invalid")
        if (
            relink_manifest.get("format")
            != "simplelogin-owned-provider-relink-manifest"
        ):
            raise ComplianceError("relink manifest format is invalid")

        fork = provenance.get("fork", {})
        upstream = provenance.get("upstream", {})
        image = provenance.get("image", {})
        if (
            provenance.get("format_version") != self.policy.bundle_format_version
            or fork.get("source") != self.policy.fork_source_url
            or upstream.get("source") != self.policy.upstream_source_url
            or provenance.get("external_images")
            != dict(sorted(self.policy.external_images.items()))
        ):
            raise ComplianceError("bundle provenance policy differs")
        fork_revision = str(fork.get("revision", ""))
        upstream_revision = str(upstream.get("revision", ""))
        if not REVISION_RE.fullmatch(fork_revision) or not REVISION_RE.fullmatch(
            upstream_revision
        ):
            raise ComplianceError("bundle Git provenance is not exact")
        if (
            not IMAGE_SHA256_RE.fullmatch(str(image.get("id", "")))
            or image.get("platform") != "linux/amd64"
            or not image.get("rootfs_diff_ids")
            or any(
                not IMAGE_SHA256_RE.fullmatch(str(digest))
                for digest in image.get("rootfs_diff_ids", [])
            )
        ):
            raise ComplianceError("bundle image provenance is incomplete")
        expected_labels = {
            "org.opencontainers.image.licenses": self.policy.license_expression,
            "org.opencontainers.image.revision": fork_revision,
            "org.opencontainers.image.source": self.policy.fork_source_url,
            "org.opencontainers.image.upstream.revision": upstream_revision,
        }
        labels = image.get("labels", {})
        if {key: labels.get(key) for key in expected_labels} != expected_labels:
            raise ComplianceError("bundle image labels differ from provenance")
        runtime_raw = provenance.get("runtime_inventory", {})
        scans = runtime_raw.get("scans_complete", {})
        bundled_runtime = RuntimeInventory(
            python_distributions=tuple(runtime_raw.get("python_distributions", [])),
            debian_packages=tuple(runtime_raw.get("debian_packages", [])),
            npm_packages=tuple(runtime_raw.get("npm_packages", [])),
            executable_names=tuple(runtime_raw.get("executable_names", [])),
            python_scan_complete=scans.get("python") is True,
            debian_scan_complete=scans.get("debian") is True,
            npm_scan_complete=scans.get("npm") is True,
            executable_scan_complete=scans.get("executables") is True,
            native_scan_complete=scans.get("native") is True,
        )
        validate_runtime_inventory(bundled_runtime, self.policy)

        source_components = source_manifest.get("components")
        if not isinstance(source_components, list) or not source_components:
            raise ComplianceError("source component inventory is empty")
        root_component = sbom.get("metadata", {}).get("component", {})
        all_sbom_components = [root_component, *sbom.get("components", [])]
        sbom_component_map = {
            component.get("bom-ref"): component for component in all_sbom_components
        }
        if (
            len(sbom_component_map) != len(all_sbom_components)
            or None in sbom_component_map
        ):
            raise ComplianceError("SBOM component references are absent or duplicated")
        sbom_refs = set(sbom_component_map)
        source_refs = {component.get("bom_ref") for component in source_components}
        if len(source_refs) != len(source_components) or None in source_refs:
            raise ComplianceError(
                "source component references are absent or duplicated"
            )
        native_refs = {
            component["bom-ref"]
            for component in sbom.get("components", [])
            if component.get("type") == "file"
        }
        if sbom_refs - native_refs != source_refs:
            raise ComplianceError("SBOM and source-manifest component sets differ")

        root_ref = provenance.get("root_component_ref")
        if root_ref != root_component.get("bom-ref") or root_ref not in source_refs:
            raise ComplianceError("SBOM root component differs from provenance")
        metadata_properties = {
            item.get("name"): item.get("value")
            for item in sbom.get("metadata", {}).get("properties", [])
        }
        if metadata_properties != {
            "owned-provider:image-id": image["id"],
            "owned-provider:repository-revision": fork_revision,
            "owned-provider:upstream-revision": upstream_revision,
        }:
            raise ComplianceError("SBOM metadata differs from provenance")
        expected_serial = (
            f"urn:uuid:{uuid.uuid5(NATIVE_REF_NAMESPACE, str(image['id']))}"
        )
        if sbom.get("serialNumber") != expected_serial or sbom.get("version") != 1:
            raise ComplianceError("SBOM identity is not deterministic")

        dependency_records = sbom.get("dependencies", [])
        dependency_map = {
            record.get("ref"): record.get("dependsOn") for record in dependency_records
        }
        if (
            len(dependency_map) != len(dependency_records)
            or set(dependency_map) != sbom_refs
        ):
            raise ComplianceError("SBOM dependency graph coverage differs")
        for reference, dependencies in dependency_map.items():
            if (
                not isinstance(dependencies, list)
                or dependencies != sorted(set(dependencies))
                or not set(dependencies) <= sbom_refs
            ):
                raise ComplianceError(f"SBOM dependency graph is invalid: {reference}")

        sbom_native: dict[str, dict[str, Any]] = {}
        native_ref_to_path: dict[str, str] = {}
        native_owner_refs: dict[str, str] = {}
        for component in sbom.get("components", []):
            if component.get("type") != "file":
                continue
            properties = {
                item.get("name"): item.get("value")
                for item in component.get("properties", [])
            }
            path = str(properties.get("owned-provider:native-path", ""))
            owner = properties.get("owned-provider:native-owner")
            hashes = {
                item.get("alg"): item.get("content")
                for item in component.get("hashes", [])
            }
            if (
                not path.startswith("/")
                or owner not in source_refs
                or "SHA-256" not in hashes
            ):
                raise ComplianceError(
                    "native SBOM component lacks path, owner, or digest"
                )
            validate_relative_path(path.removeprefix("/"))
            validate_digest(
                str(hashes["SHA-256"]), field_name=f"native digest for {path}"
            )
            if PurePosixPath(path).name in self.policy.forbidden_executables:
                raise ComplianceError(f"development native executable shipped: {path}")
            try:
                needed = json.loads(
                    str(properties.get("owned-provider:native-needed", ""))
                )
            except json.JSONDecodeError as error:
                raise ComplianceError(
                    "native SBOM dependency metadata is invalid"
                ) from error
            if not isinstance(needed, list):
                raise ComplianceError("native SBOM dependency metadata is not a list")
            normalized_needed = []
            for dependency in needed:
                soname = str(dependency.get("soname", ""))
                resolved_path = str(dependency.get("resolved_path", ""))
                if not soname or not resolved_path.startswith("/"):
                    raise ComplianceError(f"native dependency is unresolved: {path}")
                normalized_needed.append(
                    {"resolved_path": resolved_path, "soname": soname}
                )
            if normalized_needed != sorted(
                normalized_needed,
                key=lambda item: (item["soname"], item["resolved_path"]),
            ):
                raise ComplianceError(
                    f"native dependency metadata is not sorted: {path}"
                )
            if path in sbom_native:
                raise ComplianceError(f"native SBOM path is duplicated: {path}")
            sbom_native[path] = {
                "dependencies": normalized_needed,
                "sha256": hashes["SHA-256"],
            }
            native_reference = str(component["bom-ref"])
            native_ref_to_path[native_reference] = path
            native_owner_refs[native_reference] = str(owner)
        for path, record in sbom_native.items():
            targets = [
                dependency["resolved_path"] for dependency in record["dependencies"]
            ]
            if not set(targets) <= sbom_native.keys():
                raise ComplianceError(
                    f"native dependency target is not inventoried: {path}"
                )
            graph_targets = [
                native_ref_to_path[reference]
                for reference in dependency_map[
                    next(
                        ref
                        for ref, native_path in native_ref_to_path.items()
                        if native_path == path
                    )
                ]
            ]
            if sorted(set(targets)) != sorted(graph_targets):
                raise ComplianceError(
                    f"native CycloneDX dependency edges differ: {path}"
                )

        if expected_native is not None:
            observed_native = {
                record.path: {
                    "dependencies": [
                        {
                            "resolved_path": dependency.resolved_path,
                            "soname": dependency.soname,
                        }
                        for dependency in sorted(
                            record.dependencies,
                            key=lambda item: (item.soname, item.resolved_path),
                        )
                    ],
                    "sha256": record.sha256,
                }
                for record in expected_native
            }
            if sbom_native != observed_native:
                raise ComplianceError("bundle native inventory differs from the image")
        notice_components: list[ComponentRecord] = []
        for component in source_components:
            bom_ref = str(component.get("bom_ref", ""))
            sbom_component = sbom_component_map[bom_ref]
            dependencies = component.get("dependencies")
            if (
                not isinstance(dependencies, list)
                or dependencies != sorted(set(dependencies))
                or not set(dependencies) <= source_refs
            ):
                raise ComplianceError(
                    f"component dependency metadata is invalid: {bom_ref}"
                )
            licenses = sbom_component.get("licenses", [])
            expression = str(component.get("license", ""))
            validate_license(expression, self.policy)
            if licenses != [{"expression": expression}]:
                raise ComplianceError(
                    f"component license differs across manifests: {bom_ref}"
                )
            properties = {
                item.get("name"): item.get("value")
                for item in sbom_component.get("properties", [])
            }
            license_path = validate_relative_path(
                str(component.get("license_path", ""))
            )
            if (
                properties.get("owned-provider:license-path") != license_path
                or license_path not in files
                or not files[license_path].strip()
            ):
                raise ComplianceError(
                    f"component license text is absent: {license_path}"
                )
            source = component.get("source")
            if not isinstance(source, dict) or not source.get("url"):
                raise ComplianceError("component source URL is absent")
            validate_url(str(source["url"]), field_name="component source URL")
            if sbom_component.get("externalReferences") != [
                {"type": "distribution", "url": source["url"]}
            ]:
                raise ComplianceError(
                    f"component source URL differs across manifests: {bom_ref}"
                )
            source_required = self.policy.requires_source(expression)
            if component.get("source_required") is not source_required:
                raise ComplianceError(f"component source obligation differs: {bom_ref}")
            raw_materials = source.get("materials")
            if not isinstance(raw_materials, list):
                raise ComplianceError(f"source materials are not a list: {bom_ref}")
            if source_required is not bool(raw_materials):
                raise ComplianceError(
                    f"non-copyleft source metadata is inconsistent: {bom_ref}"
                )
            source_materials: list[SourceMaterial] = []
            source_paths: set[str] = set()
            for raw_material in raw_materials:
                source_path = validate_relative_path(
                    str(raw_material.get("archive_path", ""))
                )
                digest = validate_digest(
                    str(raw_material.get("sha256", "")), field_name="source digest"
                )
                download_url = validate_url(
                    str(raw_material.get("download_url", "")),
                    field_name="source download URL",
                )
                if source_path in source_paths:
                    raise ComplianceError(
                        f"source material path is duplicated: {bom_ref}"
                    )
                source_paths.add(source_path)
                if (
                    source_path not in files
                    or sha256_bytes(files[source_path]) != digest
                ):
                    raise ComplianceError(
                        f"corresponding source is absent or changed: {source_path}"
                    )
                validate_source_archive(source_path, files[source_path])
                source_materials.append(
                    SourceMaterial(
                        path=source_path,
                        download_url=download_url,
                        sha256=digest,
                    )
                )
            expected_source_property = (
                json.dumps(
                    raw_materials,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if raw_materials
                else None
            )
            if (
                properties.get("owned-provider:source-materials")
                != expected_source_property
            ):
                raise ComplianceError(
                    f"source materials differ across manifests: {bom_ref}"
                )
            hashes = {
                item.get("alg"): item.get("content")
                for item in sbom_component.get("hashes", [])
            }
            notice_components.append(
                ComponentRecord(
                    bom_ref=bom_ref,
                    name=str(component.get("name", "")),
                    version=str(component.get("version", "")),
                    component_type=str(sbom_component.get("type", "")),
                    ecosystem=str(properties.get("owned-provider:ecosystem", "")),
                    purl=str(component.get("purl", "")),
                    license_expression=expression,
                    license_path=license_path,
                    source_url=str(source["url"]),
                    source_materials=tuple(source_materials),
                    installed_sha256=hashes.get("SHA-256"),
                    copyright_notice=str(component.get("copyright_notice", "")),
                    dependencies=tuple(str(item) for item in dependencies),
                )
            )
            if (
                sbom_component.get("name") != component.get("name")
                or sbom_component.get("version") != component.get("version")
                or sbom_component.get("purl") != component.get("purl")
            ):
                raise ComplianceError(
                    f"component identity differs across manifests: {bom_ref}"
                )
        if (
            render_component_notices(notice_components)
            != files["THIRD_PARTY_NOTICES.md"]
        ):
            raise ComplianceError("third-party notices differ from component inventory")
        notice_component_map = {
            component.bom_ref: component for component in notice_components
        }
        for component in notice_components:
            owned_native = {
                reference
                for reference, owner in native_owner_refs.items()
                if owner == component.bom_ref
            }
            expected_dependencies = sorted(set(component.dependencies) | owned_native)
            if dependency_map[component.bom_ref] != expected_dependencies:
                raise ComplianceError(
                    f"CycloneDX dependency edges differ from source inventory: "
                    f"{component.bom_ref}"
                )
        component_python = {
            f"{normalize_python_name(component.name)}=={component.version}"
            for component in notice_components
            if component.ecosystem == "pypi"
        }
        component_debian = {
            f"{component.name}=={component.version}"
            for component in notice_components
            if component.ecosystem == "deb"
        }
        component_npm = {
            f"{component.name}@{component.version}"
            for component in notice_components
            if component.ecosystem == "npm"
        }
        if (
            component_python != set(bundled_runtime.python_distributions)
            or component_debian != set(bundled_runtime.debian_packages)
            or component_npm != set(bundled_runtime.npm_packages)
        ):
            raise ComplianceError(
                "SBOM package components differ from the exact runtime inventories"
            )
        root_notice = notice_component_map[str(root_ref)]
        if (
            root_notice.license_expression != self.policy.license_expression
            or root_notice.source_url != self.policy.fork_source_url
            or len(root_notice.source_materials) != 1
            or root_notice.source_materials[0].download_url
            != f"{self.policy.fork_source_url}/archive/{fork_revision}.tar.gz"
        ):
            raise ComplianceError("root source or license differs from policy")
        relink_refs = {
            record.get("component_ref") for record in relink_manifest.get("records", [])
        }
        required_relink_refs = {
            component["bom_ref"]
            for component in source_components
            if self.policy.requires_relink(str(component["license"]))
        }
        if relink_refs != required_relink_refs:
            raise ComplianceError(
                "LGPL relinking coverage differs from source inventory"
            )
        source_record_map = {
            str(component["bom_ref"]): component for component in source_components
        }
        for record in relink_manifest.get("records", []):
            linkage = str(record.get("linkage", ""))
            if linkage not in self.policy.relink_material_kinds or not record.get(
                "consumers"
            ):
                raise ComplianceError("LGPL relinking mode or consumers are absent")
            consumers = [str(consumer) for consumer in record["consumers"]]
            for consumer in consumers:
                if not consumer.startswith("/"):
                    raise ComplianceError(
                        "LGPL relinking consumer is not an absolute path"
                    )
                validate_relative_path(consumer.removeprefix("/"))
            if (
                linkage in {"dynamic", "static"}
                and not set(consumers) <= sbom_native.keys()
            ):
                raise ComplianceError(
                    "LGPL native relinking consumer is not inventoried"
                )
            materials = record.get("materials", [])
            kinds = {material.get("kind") for material in materials}
            if not self.policy.relink_material_kinds[linkage] <= kinds:
                raise ComplianceError("LGPL relinking material kinds are incomplete")
            material_pairs = {
                (str(material.get("path", "")), str(material.get("kind", "")))
                for material in materials
            }
            component_sources = {
                str(material["archive_path"])
                for material in source_record_map[str(record["component_ref"])][
                    "source"
                ]["materials"]
            }
            declared_sources = {
                path for path, kind in material_pairs if kind == "source"
            }
            if (
                str(record.get("instructions_path", "")),
                "instructions",
            ) not in material_pairs or component_sources != declared_sources:
                raise ComplianceError(
                    "LGPL relinking source or instructions differ from the component"
                )
            paths = [record.get("instructions_path")]
            paths.extend(material.get("path") for material in materials)
            for raw_path in paths:
                path = validate_relative_path(str(raw_path or ""))
                if path not in files or not files[path].strip():
                    raise ComplianceError(f"relinking material is absent: {path}")

        referenced_artifacts = {
            str(component["license_path"]) for component in source_components
        }
        referenced_artifacts.update(
            str(material["archive_path"])
            for component in source_components
            for material in component["source"]["materials"]
        )
        for record in relink_manifest.get("records", []):
            referenced_artifacts.add(str(record["instructions_path"]))
            referenced_artifacts.update(
                str(material["path"]) for material in record.get("materials", [])
            )
        expected_files = referenced_artifacts | required | {"SHA256SUMS"}
        if set(files) != expected_files:
            raise ComplianceError(
                "bundle contains an unreferenced or absent compliance artifact"
            )

        if expected_image is not None:
            actual_identity = {
                "id": image.get("id"),
                "labels": image.get("labels"),
                "platform": image.get("platform"),
                "reference": image.get("reference"),
                "rootfs_diff_ids": image.get("rootfs_diff_ids"),
            }
            expected_identity = {
                "id": expected_image.image_id,
                "labels": dict(sorted(expected_image.labels.items())),
                "platform": expected_image.platform,
                "reference": expected_image.image_reference,
                "rootfs_diff_ids": list(expected_image.rootfs_diff_ids),
            }
            if actual_identity != expected_identity:
                raise ComplianceError("bundle is not bound to the inspected image")
        if expected_runtime is not None:
            actual_runtime = provenance.get("runtime_inventory", {})
            expected_runtime_json = {
                "debian_packages": sorted(expected_runtime.debian_packages),
                "executable_names": sorted(expected_runtime.executable_names),
                "npm_packages": sorted(expected_runtime.npm_packages),
                "python_distributions": sorted(expected_runtime.python_distributions),
                "scans_complete": {
                    "debian": expected_runtime.debian_scan_complete,
                    "executables": expected_runtime.executable_scan_complete,
                    "native": expected_runtime.native_scan_complete,
                    "npm": expected_runtime.npm_scan_complete,
                    "python": expected_runtime.python_scan_complete,
                },
            }
            if actual_runtime != expected_runtime_json:
                raise ComplianceError("bundle runtime inventory differs from the image")
        if (
            expected_repository_revision
            and provenance.get("fork", {}).get("revision")
            != expected_repository_revision
        ):
            raise ComplianceError("bundle fork revision differs from the repository")
        if (
            expected_upstream_revision
            and provenance.get("upstream", {}).get("revision")
            != expected_upstream_revision
        ):
            raise ComplianceError(
                "bundle upstream revision differs from the repository"
            )
        return {
            "bundle": str(bundle),
            "component_count": len(source_refs),
            "file_count": len(files),
            "image_id": image.get("id"),
            "native_file_count": len(native_refs),
            "verified": True,
        }


class CommandRunner(Protocol):
    def run(self, args: Sequence[str]) -> str:
        ...


class SubprocessRunner:
    def run(self, args: Sequence[str]) -> str:
        return subprocess.check_output(args, text=True).strip()


class DockerImageInspector:
    """Read immutable identity and rootfs evidence from a local Docker image."""

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or SubprocessRunner()

    def inspect_identity(self, image: str) -> ImageIdentity:
        inspected = json.loads(self.runner.run(("docker", "image", "inspect", image)))
        if not isinstance(inspected, list) or len(inspected) != 1:
            raise ComplianceError(
                f"expected one Docker image inspection result: {image}"
            )
        record = inspected[0]
        image_id = str(record.get("Id", ""))
        architecture = str(record.get("Architecture", ""))
        operating_system = str(record.get("Os", ""))
        labels = record.get("Config", {}).get("Labels") or {}
        diff_ids = record.get("RootFS", {}).get("Layers") or []
        identity = ImageIdentity(
            image_reference=image,
            image_id=image_id,
            platform=f"{operating_system}/{architecture}",
            rootfs_diff_ids=tuple(str(item) for item in diff_ids),
            labels={str(key): str(value) for key, value in labels.items()},
        )
        if not IMAGE_SHA256_RE.fullmatch(identity.image_id):
            raise ComplianceError("Docker image did not expose an immutable image ID")
        return identity

    def _container_command(self, image: str, executable: str, *args: str) -> str:
        return self.runner.run(
            (
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--user",
                "0:0",
                "--entrypoint",
                executable,
                image,
                *args,
            )
        )

    def inspect_runtime(
        self, image: str, policy: DistributionPolicy, *, native_complete: bool
    ) -> RuntimeInventory:
        python_scanner = textwrap.dedent(
            r"""
            import importlib.metadata as metadata
            import json
            import os
            import re

            search_paths = set()
            for root in ("/code", "/opt", "/usr/local/lib", "/usr/lib"):
                if not os.path.isdir(root):
                    continue
                for directory, subdirs, _files in os.walk(root, followlinks=False):
                    if os.path.basename(directory) == "site-packages":
                        search_paths.add(directory)
                        subdirs[:] = []

            distributions = list(metadata.distributions())
            for path in sorted(search_paths):
                distributions.extend(metadata.distributions(path=[path]))
            installed = {
                re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower()
                + "=="
                + distribution.version
                for distribution in distributions
                if distribution.metadata["Name"]
            }
            print(json.dumps(sorted(installed)))
            """
        ).strip()
        python_output = self._container_command(
            image,
            RUNTIME_PYTHON,
            "-c",
            python_scanner,
        )
        debian_output = self._container_command(
            image,
            "/bin/sh",
            "-c",
            "dpkg-query -W -f='${binary:Package}==${Version}\\n' | LC_ALL=C sort -u",
        )
        npm_scanner = textwrap.dedent(
            r"""
            import json
            import os

            root = "/code/static/node_modules"
            packages = set()
            def walk_error(error):
                raise error

            if os.path.isdir(root):
                for directory, subdirs, files in os.walk(
                    root,
                    followlinks=False,
                    onerror=walk_error,
                ):
                    subdirs[:] = [name for name in subdirs if name != ".bin"]
                    if "package.json" not in files:
                        continue
                    relative = os.path.relpath(directory, root).split(os.sep)
                    if "node_modules" in relative:
                        relative = relative[len(relative) - 1 - relative[::-1].index("node_modules") + 1:]
                    if len(relative) not in (1, 2) or (len(relative) == 2 and not relative[0].startswith("@")):
                        continue
                    try:
                        with open(os.path.join(directory, "package.json"), encoding="utf-8") as stream:
                            package = json.load(stream)
                    except (OSError, UnicodeError, json.JSONDecodeError):
                        raise SystemExit(f"invalid installed npm package metadata: {directory}")
                    name = package.get("name")
                    version = package.get("version")
                    if not name or not version:
                        raise SystemExit(f"incomplete installed npm package metadata: {directory}")
                    packages.add(f"{name}@{version}")
            print(json.dumps(sorted(packages)))
            """
        ).strip()
        npm_output = self._container_command(image, RUNTIME_PYTHON, "-c", npm_scanner)
        executable_probe = (
            canonical_json(sorted(policy.forbidden_executables)).decode().strip()
        )
        executable_scanner = textwrap.dedent(
            r"""
            import json
            import os
            import sys

            candidates = set(json.loads(sys.argv[1]))
            installed = set()
            for root in ("/bin", "/code", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local", "/opt"):
                if not os.path.isdir(root):
                    continue
                for directory, _subdirs, files in os.walk(root, followlinks=False):
                    installed.update(candidates.intersection(files))
            print(json.dumps(sorted(installed)))
            """
        ).strip()
        executable_output = self._container_command(
            image,
            RUNTIME_PYTHON,
            "-c",
            executable_scanner,
            executable_probe,
        )
        return RuntimeInventory(
            python_distributions=tuple(json.loads(python_output)),
            debian_packages=tuple(line for line in debian_output.splitlines() if line),
            npm_packages=tuple(json.loads(npm_output)),
            executable_names=tuple(json.loads(executable_output)),
            python_scan_complete=True,
            debian_scan_complete=True,
            npm_scan_complete=True,
            executable_scan_complete=True,
            native_scan_complete=native_complete,
        )

    def inspect_embedded_provenance(self, image: str) -> Mapping[str, object]:
        output = self._container_command(
            image,
            RUNTIME_PYTHON,
            "-c",
            "import json; from pathlib import Path; "
            "from app.build_info import BUILD_TIME, SHA1; "
            "forbidden = ('/code/tests', '/code/.env', "
            "'/code/local_data/private-pgp.asc', '/code/local_data/jwtRS256.key', "
            "'/code/local_data/dkim.key', '/code/local_data/key.pem', "
            "'/code/local_data/test_words.txt'); "
            "print(json.dumps({'revision': SHA1, 'source_date_epoch': BUILD_TIME, "
            "'owned_provider_runtime_present': Path('/code/.owned-provider').exists(), "
            "'forbidden_fixture_paths_present': [p for p in forbidden if Path(p).exists()], "
            "'static_upload_files_present': [str(p) for p in "
            "Path('/code/static/upload').rglob('*') if p.is_file() or p.is_symlink()]}, "
            "sort_keys=True))",
        )
        value = json.loads(output)
        if not isinstance(value, dict):
            raise ComplianceError("runtime provenance probe did not return an object")
        return value

    def inspect_native(self, image: str) -> tuple[ObservedNativeRecord, ...]:
        scanner = textwrap.dedent(
            r"""
            import hashlib
            import json
            import os
            import re
            import subprocess

            os.environ["LC_ALL"] = "C"
            roots = (
                "/bin",
                "/code",
                "/lib",
                "/lib32",
                "/lib64",
                "/opt",
                "/sbin",
                "/usr/bin",
                "/usr/lib",
                "/usr/lib32",
                "/usr/lib64",
                "/usr/local",
                "/usr/sbin",
            )
            paths = set()
            def walk_error(error):
                raise error

            for root in roots:
                if not os.path.exists(root):
                    continue
                for directory, subdirs, files in os.walk(
                    root, followlinks=False, onerror=walk_error
                ):
                    subdirs[:] = [name for name in subdirs if name != "__pycache__"]
                    for name in files:
                        candidate = os.path.join(directory, name)
                        try:
                            if os.path.islink(candidate) or not os.path.isfile(candidate):
                                continue
                            with open(candidate, "rb") as stream:
                                if stream.read(4) != b"\x7fELF":
                                    continue
                            paths.add(os.path.realpath(candidate))
                        except OSError as error:
                            raise SystemExit(f"cannot inventory native file {candidate}: {error}")

            records = []
            for path in sorted(paths):
                with open(path, "rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                completed = subprocess.run(("ldd", path), capture_output=True, text=True, check=False)
                output = completed.stdout + completed.stderr
                if completed.returncode and not any(
                    marker in output
                    for marker in ("statically linked", "not a dynamic executable")
                ):
                    raise SystemExit(f"ldd failed for {path}: {output.strip()}")
                dependencies = []
                for line in output.splitlines():
                    stripped = line.strip()
                    if (
                        not stripped
                        or stripped.startswith("linux-vdso")
                        or stripped in {"statically linked", "not a dynamic executable"}
                    ):
                        continue
                    missing = re.match(r"^(\S+) => not found$", stripped)
                    if missing:
                        dependencies.append({"soname": missing.group(1), "resolved_path": ""})
                        continue
                    linked = re.match(r"^(\S+) => (/\S+) \(0x[0-9a-fA-F]+\)$", stripped)
                    direct = re.match(r"^(/\S+) \(0x[0-9a-fA-F]+\)$", stripped)
                    if linked:
                        dependencies.append({"soname": linked.group(1), "resolved_path": os.path.realpath(linked.group(2))})
                    elif direct:
                        dependencies.append({"soname": os.path.basename(direct.group(1)), "resolved_path": os.path.realpath(direct.group(1))})
                    else:
                        raise SystemExit(f"unrecognized ldd output for {path}: {stripped}")
                records.append({"dependencies": dependencies, "path": path, "sha256": digest})
            print(json.dumps(records, sort_keys=True, separators=(",", ":")))
            """
        ).strip()
        output = self._container_command(image, RUNTIME_PYTHON, "-c", scanner)
        raw = json.loads(output)
        records = tuple(
            ObservedNativeRecord(
                path=str(record["path"]),
                sha256=str(record["sha256"]),
                dependencies=tuple(
                    NativeDependency(
                        soname=str(dependency["soname"]),
                        resolved_path=str(dependency["resolved_path"]),
                    )
                    for dependency in record["dependencies"]
                ),
            )
            for record in raw
        )
        for record in records:
            validate_digest(
                record.sha256, field_name=f"native digest for {record.path}"
            )
            for dependency in record.dependencies:
                if not dependency.resolved_path:
                    raise ComplianceError(
                        f"image contains an unresolved native dependency: "
                        f"{record.path} -> {dependency.soname}"
                    )
        return records


@dataclass(frozen=True)
class SourceRequest:
    url: str
    algorithm: str
    digest: str
    maximum_bytes: int = MAX_BUNDLE_FILE_BYTES


class ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        validate_url(new_url, field_name="redirected source URL")
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


class SourceRetriever:
    """Fetch one public source archive with byte and digest bounds."""

    def retrieve(self, request: SourceRequest) -> bytes:
        validate_url(request.url, field_name="source download URL")
        if request.algorithm not in hashlib.algorithms_available:
            raise ComplianceError(f"unsupported source digest: {request.algorithm}")
        if request.maximum_bytes <= 0 or request.maximum_bytes > MAX_BUNDLE_FILE_BYTES:
            raise ComplianceError("source byte limit is outside the policy bound")
        digest_size = hashlib.new(request.algorithm).digest_size * 2
        if not re.fullmatch(rf"[0-9a-f]{{{digest_size}}}", request.digest):
            raise ComplianceError("source digest has the wrong format")
        http_request = urllib.request.Request(
            request.url,
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": "owned-provider-source/1",
            },
        )
        chunks: list[bytes] = []
        size = 0
        hasher = hashlib.new(request.algorithm)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), ValidatingRedirectHandler()
        )
        with opener.open(http_request, timeout=30) as response:
            final_url = response.geturl()
            validate_url(final_url, field_name="redirected source URL")
            if response.headers.get("Content-Encoding") not in (None, "identity"):
                raise ComplianceError("source server returned encoded content")
            while True:
                chunk = response.read(
                    min(1024 * 1024, request.maximum_bytes - size + 1)
                )
                if not chunk:
                    break
                size += len(chunk)
                if size > request.maximum_bytes:
                    raise ComplianceError("source archive exceeds its byte limit")
                hasher.update(chunk)
                chunks.append(chunk)
        if hasher.hexdigest() != request.digest:
            raise ComplianceError("downloaded source archive digest differs")
        return b"".join(chunks)


def _component_from_json(raw: Mapping[str, Any]) -> ComponentRecord:
    return ComponentRecord(
        bom_ref=str(raw["bom_ref"]),
        name=str(raw["name"]),
        version=str(raw["version"]),
        component_type=str(raw["component_type"]),
        ecosystem=str(raw["ecosystem"]),
        purl=str(raw["purl"]),
        license_expression=str(raw["license_expression"]),
        license_path=str(raw["license_path"]),
        source_url=str(raw["source_url"]),
        source_materials=tuple(
            SourceMaterial(
                path=str(material["path"]),
                download_url=str(material["download_url"]),
                sha256=str(material["sha256"]),
            )
            for material in raw.get("source_materials", [])
        ),
        installed_sha256=raw.get("installed_sha256"),
        copyright_notice=str(raw.get("copyright_notice", "")),
        dependencies=tuple(str(item) for item in raw.get("dependencies", [])),
    )


def bundle_input_from_json(raw: Mapping[str, Any]) -> BundleInput:
    provenance_raw = raw["provenance"]
    image_raw = provenance_raw["image"]
    runtime_raw = provenance_raw["runtime"]
    provenance = ProvenanceRecord(
        repository_revision=str(provenance_raw["repository_revision"]),
        upstream_revision=str(provenance_raw["upstream_revision"]),
        image=ImageIdentity(
            image_reference=str(image_raw["image_reference"]),
            image_id=str(image_raw["image_id"]),
            platform=str(image_raw["platform"]),
            rootfs_diff_ids=tuple(str(item) for item in image_raw["rootfs_diff_ids"]),
            labels={str(key): str(value) for key, value in image_raw["labels"].items()},
        ),
        root_component_ref=str(provenance_raw["root_component_ref"]),
        runtime=RuntimeInventory(
            python_distributions=tuple(
                str(item) for item in runtime_raw["python_distributions"]
            ),
            debian_packages=tuple(str(item) for item in runtime_raw["debian_packages"]),
            npm_packages=tuple(str(item) for item in runtime_raw["npm_packages"]),
            executable_names=tuple(
                str(item) for item in runtime_raw["executable_names"]
            ),
            python_scan_complete=bool(runtime_raw["python_scan_complete"]),
            debian_scan_complete=bool(runtime_raw["debian_scan_complete"]),
            npm_scan_complete=bool(runtime_raw["npm_scan_complete"]),
            executable_scan_complete=bool(runtime_raw["executable_scan_complete"]),
            native_scan_complete=bool(runtime_raw["native_scan_complete"]),
        ),
    )
    native = tuple(
        NativeRecord(
            path=str(record["path"]),
            sha256=str(record["sha256"]),
            owner_ref=str(record["owner_ref"]),
            dependencies=tuple(
                NativeDependency(
                    soname=str(dependency["soname"]),
                    resolved_path=str(dependency["resolved_path"]),
                )
                for dependency in record.get("dependencies", [])
            ),
        )
        for record in raw.get("native", [])
    )
    relinking = tuple(
        RelinkRecord(
            component_ref=str(record["component_ref"]),
            linkage=str(record["linkage"]),
            consumers=tuple(str(item) for item in record["consumers"]),
            instructions_path=str(record["instructions_path"]),
            material_paths=tuple(str(item["path"]) for item in record["materials"]),
            material_kinds=tuple(str(item["kind"]) for item in record["materials"]),
        )
        for record in raw.get("relinking", [])
    )
    return BundleInput(
        provenance=provenance,
        components=tuple(_component_from_json(item) for item in raw["components"]),
        native=native,
        relinking=relinking,
    )


def read_artifacts(
    root: Path,
    value: BundleInput,
    *,
    fetch_sources: bool = False,
    retriever: SourceRetriever | None = None,
) -> dict[str, bytes]:
    if not root.is_dir() or root.is_symlink():
        raise ComplianceError(f"artifact root is not a real directory: {root}")
    artifacts: dict[str, bytes] = {}
    source_by_path = {
        material.path: material
        for component in value.components
        for material in component.source_materials
    }
    for relative in expected_artifact_paths(value):
        source = root / relative
        if source.is_symlink():
            raise ComplianceError(f"artifact is a symlink: {relative}")
        if source.is_file():
            artifacts[relative] = read_bounded_file(source)
            continue
        material = source_by_path.get(relative)
        if not fetch_sources or material is None:
            raise ComplianceError(f"artifact is absent or not regular: {relative}")
        artifacts[relative] = (retriever or SourceRetriever()).retrieve(
            SourceRequest(
                url=material.download_url,
                algorithm="sha256",
                digest=material.sha256,
            )
        )
    return artifacts


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    default_policy = script_dir.parent / "distribution-policy.toml"
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=default_policy)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate")
    generate.add_argument("--input", required=True, type=Path)
    generate.add_argument("--artifact-root", required=True, type=Path)
    generate.add_argument("--output", required=True, type=Path)
    generate.add_argument("--fetch-sources", action="store_true")

    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", required=True, type=Path)

    inspect_image = subparsers.add_parser("inspect-image")
    inspect_image.add_argument("--image", required=True)

    args = parser.parse_args()
    policy = DistributionPolicy.load(args.policy)
    if args.command == "generate":
        raw = json.loads(read_bounded_file(args.input, maximum_bytes=64 * 1024 * 1024))
        value = bundle_input_from_json(raw)
        artifacts = read_artifacts(
            args.artifact_root,
            value,
            fetch_sources=args.fetch_sources,
        )
        output = ComplianceBundleBuilder(policy).build(value, artifacts, args.output)
        print(
            canonical_json({"bundle": str(output), "generated": True}).decode(), end=""
        )
    elif args.command == "verify":
        result = ComplianceBundleVerifier(policy).verify(args.bundle)
        print(canonical_json(result).decode(), end="")
    else:
        inspector = DockerImageInspector()
        identity = inspector.inspect_identity(args.image)
        native = inspector.inspect_native(args.image)
        runtime = inspector.inspect_runtime(args.image, policy, native_complete=True)
        validate_runtime_inventory(runtime, policy)
        print(
            canonical_json(
                {
                    "image": {
                        "image_id": identity.image_id,
                        "image_reference": identity.image_reference,
                        "labels": dict(sorted(identity.labels.items())),
                        "platform": identity.platform,
                        "rootfs_diff_ids": list(identity.rootfs_diff_ids),
                    },
                    "native": [
                        {
                            "dependencies": [
                                {
                                    "resolved_path": dependency.resolved_path,
                                    "soname": dependency.soname,
                                }
                                for dependency in record.dependencies
                            ],
                            "path": record.path,
                            "sha256": record.sha256,
                        }
                        for record in native
                    ],
                    "runtime": {
                        "debian_packages": list(runtime.debian_packages),
                        "debian_scan_complete": runtime.debian_scan_complete,
                        "executable_names": list(runtime.executable_names),
                        "executable_scan_complete": runtime.executable_scan_complete,
                        "native_scan_complete": runtime.native_scan_complete,
                        "npm_packages": list(runtime.npm_packages),
                        "npm_scan_complete": runtime.npm_scan_complete,
                        "python_distributions": list(runtime.python_distributions),
                        "python_scan_complete": runtime.python_scan_complete,
                    },
                }
            ).decode(),
            end="",
        )


if __name__ == "__main__":
    main()
