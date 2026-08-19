# Runtime and distribution license assessment

This is an artifact and deployment-path assessment for the owned-provider
build, not a conclusion that every possible redistribution is cleared. It
distinguishes running the default stack from conveying image bytes.

## Packaged artifacts and provenance

The default command builds two local images from this repository:

1. `simplelogin-owned-provider-upstream:<FORK_COMMIT>` from the root
   Dockerfile, including Python dependencies and pinned frontend dependencies.
2. `simplelogin-owned-provider:<FORK_COMMIT>` from the operations
   Dockerfile, inheriting the first image and adding the unprivileged runtime.

The second image runs `app`, `email`, `job-runner`, `observer`, `synthetic`, and
all tools-profile operations. The same image executes `tar` for volume export
and restore. PostgreSQL and Redis are digest-pinned third-party images pulled
by Compose. Mailpit is test-profile only.

Both locally built images now carry these exact labels:

```text
org.opencontainers.image.source=https://github.com/mateoltd/simplelogin-owned-provider
org.opencontainers.image.revision=<exact owned-provider Git commit>
org.opencontainers.image.upstream.revision=dbc45fcce4e8e6b4fa615cc729ca95a67bf75266
org.opencontainers.image.licenses=AGPL-3.0-only
```

The build refuses a dirty worktree, so the revision is not a false mapping. It
streams the exact commit through `git archive` for both Docker build contexts;
checkout mtimes and ignored runtime state therefore cannot change the layers.
The local build disables BuildKit's implicit time-varying attestation so two
no-cache builds have one comparable image identity; reviewed provenance remains
the OCI label set and the image-bound compliance bundle described below.
`SOURCE_DATE_EPOCH` is the fork commit timestamp in the CPython builder and
runtime image. The shipped filesystem is copied from a timestamp-normalized
assembly stage into one scratch-image layer, fixing interpreter metadata,
bytecode mode, file metadata, and OCI creation time to that reviewed commit.
The Python and frontend manifests declare `AGPL-3.0-only`, matching the root
license, and default web navigation links to the fork source. Run
`owned-provider distribution-audit` only after generating the compliance bundle
described below. The command now binds that bundle to the inspected local image
ID and rootfs layers, rescans its exact Python, npm, Debian, executable, and
native ELF inventories, and fails if the recorded inventory differs.
The server image builds CPython 3.12.13 from the hash-pinned official source and
dynamically links its optional compression, database, FFI, terminal, crypto,
and XML modules to the inventoried Ubuntu libraries. This avoids the static
third-party payload and missing LGPL relinking inputs in a stripped standalone
interpreter. Tk is never built because the application has no GUI path. The
build also removes `pip`, `ensurepip`, `venv`, headers, configuration tools,
`2to3`, IDLE, and pydoc helpers. The audit searches every Python package root
and executable location under `/code`, `/opt`, and the system roots instead of
trusting `PATH` alone, and rejects any unresolved shared-library dependency.
Source-built extension modules are deterministically stripped of debug paths
and linker build IDs, and their installed-wheel `RECORD` hashes are recomputed
before the runtime filesystem is normalized. Import-smoke bytecode and the
non-runtime `ldconfig` auxiliary cache are removed from the conveyed layer.

## Copyleft inventory on default paths

| Component | License conclusion | Actual packaged/default path | Required action when conveying bytes |
| --- | --- | --- | --- |
| Owned-provider and SimpleLogin fork | AGPL-3.0-only | Application code is loaded by every service and served over the network. | Keep the exact fork commit publicly retrievable, retain license/notices, and provide corresponding source including build and operations scripts. Network users must receive a clear source route. |
| `intro.js 2.9.3` | AGPL-3.0 | Compiled frontend dependency served by normal pages. | Include its license and source in the corresponding-source/notices set. |
| `qrious 4.0.2` | GPL-3.0 | Compiled frontend QR implementation used by MFA pages. | Include license and corresponding source for the distributed frontend artifact. |
| `Unidecode 1.1.2` | GPL | Python runtime package used in application normalization paths. | Include license and corresponding source; treat it as runtime, not tooling. |
| GnuPG and supporting `libassuan`, `libgcrypt`, `libgpg-error` | GnuPG is GPL; supporting libraries are LGPL | `gpg` remains in the image and is the default PGP implementation when `USE_RUST_PGP` is false. | Include notices and matching source for the installed Ubuntu package versions. Preserve dynamic-link and relinking rights for LGPL libraries. |
| GNU `tar` | GPL | Remains in the final image and is invoked by backup/export and restore. | Include its license and matching Ubuntu source when the image is conveyed. |
| `psycopg2 2.9.12` | LGPL-3.0-or-later with OpenSSL exception | Core PostgreSQL client for every stateful service, built from source and dynamically linked to the inventoried Ubuntu `libpq`. | Include its exact source and license, trace every native dependency, and preserve dynamic replacement rights. |
| `jwcrypto 1.5.8` | LGPL-3.0-or-later | Active OIDC/JWS runtime. | Retain its license/source and LGPL replacement/relinking rights. |
| `certifi 2026.7.22` | MPL-2.0 | Runtime CA bundle used on outbound TLS paths. | Include its exact license and source in the conveyed artifact's notices/source set. |
| `crontab 0.22.8` | LGPL | Packaged through yacron, but no yacron service runs by default. | Still include license/source if conveying the image because the bytes are present. |
| Ubuntu `libc6` | LGPL | Loaded by all image processes. | Retain notices and include the exact source selected by the pinned Ubuntu snapshot. |
| `tld 0.13.2` | GPL/LGPL/MPL tri-license | Runtime mail/domain parsing dependency. | Select and record the MPL option for a conveyed build and retain its notice/source. |
| `pylint`, `djlint`, `astroid`, Black, pytest, tqdm, virtualenv | GPL/LGPL/permissive development tools | No longer installed because production uses `uv sync --locked --no-dev`. | No production-image obligation for bytes that are absent. Source checkout development remains governed by each tool's license. |
| `gcc`, Binutils, Git | GPL build tools | Build stages contain them; the final runtime policy rejects their packages and executables. | The executable image audit must prove they are absent. |

## Other default images

Compose pulls PostgreSQL rather than repackaging it and pulls Redis 7.4.9 by
digest. Normal local use is not image conveyance. Mirroring, exporting, or
shipping those images is a separate distribution act: retain PostgreSQL's
license, and explicitly approve Redis 7.4's RSALv2/SSPLv1 terms before doing so.
The test-only Mailpit image needs the same review only if it is redistributed.

## Deterministic compliance bundle

`distribution-policy.toml` is the fail-closed decision record. It pins the fork
and upstream source locations, CycloneDX and bundle format versions, copyleft
source/relinking decision tables, prohibited runtime development tooling, and
the declaration that PostgreSQL, Redis, Mailpit, and the external Mail Edge
service are referenced rather than conveyed in the application image. Changing
the bytes being conveyed requires changing that declaration and repeating the
review.

`scripts/distribution_bundle.py` accepts a reviewed inventory for one exact
image and atomically creates:

- canonical CycloneDX 1.6 JSON with no wall-clock timestamp, a deterministic
  serial number, package dependency edges, and each native file, digest, owner,
  and resolved `DT_NEEDED` edge;
- notices derived from the same component records as the SBOM;
- a source manifest mapping every component to its license text and HTTPS source
  location, plus exact download URLs, SHA-256 values, and one or more safe source
  materials for every policy-classified copyleft component (including the
  clear-signed `.dsc` and archive parts for multipart Debian source packages);
- an LGPL materials manifest requiring consumers, linkage mode, replacement
  instructions, and the policy-required source/object/link inputs;
- fork, upstream, image ID, platform, rootfs layer, OCI-label, runtime-inventory,
  and referenced-image provenance; and
- one strictly sorted `SHA256SUMS` covering the exact bundle file set.

All archive member paths and links are checked before inclusion, and Debian
source control files must be clear-signed and carry the fields that bind every
multipart source archive. Bundle paths
must be normalized relative POSIX paths; symlinks, special files, missing or
extra artifacts, empty license/instruction files, unknown licenses, hashless
copyleft source, incomplete scans, unresolved native links, and unowned native
files are fatal. Missing exact source archives can be downloaded with
`--fetch-sources`; downloads are HTTPS-only, identity encoded, byte bounded,
and accepted only after their declared digest matches. License texts and
relinking materials are never synthesized or downloaded from an unreviewed
location.

The image-inspection phase is read-only and writes canonical evidence for the
reviewed inventory:

```sh
runtime_dir="${OWNED_PROVIDER_RUNTIME_DIR:-$PWD/.owned-provider}"
image="simplelogin-owned-provider:$(git rev-parse HEAD)"
mkdir -p "$runtime_dir/evidence"
python3 ops/owned-provider/scripts/distribution_bundle.py inspect-image \
  --image "$image" >"$runtime_dir/evidence/distribution-image.json"
```

The reviewed input must reconcile that evidence with exact Python and npm lock
records, Debian binary-to-source mappings, license texts, corresponding source,
native ownership, and relinking materials. Generate twice into two new
directories and require identical contents before selecting the audit bundle:

```sh
python3 ops/owned-provider/scripts/distribution_bundle.py generate \
  --input "$runtime_dir/evidence/distribution-input.json" \
  --artifact-root "$runtime_dir/evidence/distribution-materials" \
  --output "$runtime_dir/evidence/distribution-first" --fetch-sources
python3 ops/owned-provider/scripts/distribution_bundle.py generate \
  --input "$runtime_dir/evidence/distribution-input.json" \
  --artifact-root "$runtime_dir/evidence/distribution-materials" \
  --output "$runtime_dir/evidence/distribution-second" --fetch-sources
diff -ru "$runtime_dir/evidence/distribution-first" \
  "$runtime_dir/evidence/distribution-second"
test ! -e "$runtime_dir/evidence/distribution"
mv "$runtime_dir/evidence/distribution-first" \
  "$runtime_dir/evidence/distribution"
ops/owned-provider/bin/owned-provider distribution-audit
```

The final command refuses a dirty source tree, reinspects the actual local image,
walks its exact Python distributions, npm packages, and Debian packages, checks
every prohibited executable, hashes every ELF under the application,
interpreter, and system runtime roots, resolves every dynamic dependency with
`ldd`, and requires exact equality with the bundle. It then validates canonical
JSON, checksums, and semantic agreement among SBOM, source, notices, relinking,
and provenance records, exact
corresponding-source coverage, and LGPL materials. Rewriting `SHA256SUMS` after
altering another file does not bypass these semantic checks.

## Release boundary

This lane does not push or export any container image. Source publication is
closed for the owned-provider Git commit once the reviewed branch is pushed:
the image and application both point to the exact fork, and the revision label
pins the bytes to one commit.

The deterministic generator and verifier implement the required artifact
format and enforcement. Binary distribution is still not cleared merely by
having those scripts in the source tree. Before any registry push, image save,
appliance delivery, or offline bundle, the distributor must produce the bundle
for the final clean image and prove all of these gates:

1. generate an image-level SBOM including Debian packages, Python wheels,
   native libraries, and compiled frontend dependencies;
2. bundle all required license texts and copyright notices;
3. archive or make available the exact fork source and matching source for GPL
   and LGPL packages, including the native closure of source-built `psycopg2`;
4. document LGPL relinking/replacement rights and avoid anti-reverse-engineering
   terms that conflict with those rights; and
5. record whether PostgreSQL, Redis, or Mailpit image bytes are included rather
   than merely pulled by the recipient.

The same clean-room checkout must reproduce the image digest and both generated
bundle directories byte for byte. CycloneDX schema validation and an attended
license/source/relink review remain required evidence alongside the executable
audit. Until those deliverables are attached to the concrete image and every
gate passes, binary conveyance remains blocked; a passing technical audit is
evidence, not a general legal opinion.
