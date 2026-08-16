# Runtime and distribution license assessment

This is an artifact and deployment-path assessment for the owned-provider
build, not a conclusion that every possible redistribution is cleared. It
distinguishes running the default stack from conveying image bytes.

## Packaged artifacts and provenance

The default command builds two local images from this repository:

1. `simplelogin-owned-provider-upstream:<UPSTREAM_COMMIT>` from the root
   Dockerfile, including Python dependencies and compiled frontend assets.
2. `simplelogin-owned-provider:<UPSTREAM_COMMIT>` from the operations
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

The build refuses a dirty worktree, so the revision is not a false mapping.
The Python and frontend manifests declare `AGPL-3.0-only`, matching the root
license, and default web navigation links to the fork source. Run
`owned-provider distribution-audit` after every build to verify those labels,
metadata, excluded development tools, and the expected copyleft inventory.

## Copyleft inventory on default paths

| Component | License conclusion | Actual packaged/default path | Required action when conveying bytes |
| --- | --- | --- | --- |
| Owned-provider and SimpleLogin fork | AGPL-3.0-only | Application code is loaded by every service and served over the network. | Keep the exact fork commit publicly retrievable, retain license/notices, and provide corresponding source including build and operations scripts. Network users must receive a clear source route. |
| `intro.js 2.9.3` | AGPL-3.0 | Compiled frontend dependency served by normal pages. | Include its license and source in the corresponding-source/notices set. |
| `qrious 4.0.2` | GPL-3.0 | Compiled frontend QR implementation used by MFA pages. | Include license and corresponding source for the distributed frontend artifact. |
| `Unidecode 1.1.1` | GPL | Python runtime package used in application normalization paths. | Include license and corresponding source; treat it as runtime, not tooling. |
| GnuPG and supporting `libassuan`, `libgcrypt`, `libgpg-error` | GnuPG is GPL; supporting libraries are LGPL | `gpg` remains in the image and is the default PGP implementation when `USE_RUST_PGP` is false. | Include notices and matching source for the installed Ubuntu package versions. Preserve dynamic-link and relinking rights for LGPL libraries. |
| GNU `tar` | GPL | Remains in the final image and is invoked by backup/export and restore. | Include its license and matching Ubuntu source when the image is conveyed. |
| `psycopg2-binary 2.9.10` | LGPL-3.0-or-later with OpenSSL exception | Core PostgreSQL client for every stateful service. Its wheel includes native libpq/OpenSSL/Kerberos/LDAP/SASL-related closure. | Produce an exact wheel/native SBOM and corresponding-source set before binary distribution; the bundled native closure is not established by the Python lock alone. |
| `jwcrypto 0.8` | LGPL-3.0-or-later | Active OIDC/JWS runtime. | Retain its license/source and LGPL replacement/relinking rights. |
| `chardet 3.0.4` | LGPL | Runtime transitive dependency used by mail/address parsing. | Add the upstream license and source to a conveyed artifact's notices/source set. |
| `crontab 0.22.8` | LGPL | Packaged through yacron, but no yacron service runs by default. | Still include license/source if conveying the image because the bytes are present. |
| `libc6 2.35` | LGPL | Loaded by all image processes. | Apply the system-library exception analysis, retain notices, and make matching source available where required. |
| `flask-debugtoolbar-sqlalchemy 0.2.0` | GPL | Packaged as a direct runtime dependency, but the toolbar SQL panel is disabled and no default service enables it. | Bytes still trigger redistribution analysis. Remove it in the future if upstream compatibility no longer needs it. |
| `tld 0.12.6` | GPL/LGPL/MPL tri-license | Runtime mail/domain parsing dependency. | Select and record the MPL option for a conveyed build and retain its notice/source. |
| `pylint`, `djlint`, `astroid`, Black, pytest, tqdm, virtualenv | GPL/LGPL/permissive development tools | No longer installed because production uses `uv sync --locked --no-dev`. | No production-image obligation for bytes that are absent. Source checkout development remains governed by each tool's license. |
| `gcc`, Binutils, Git | GPL build tools | `gcc` and Git are explicitly purged. Binutils may remain as an indirect system package but is not invoked by a default service. | Confirm the final package SBOM before conveyance and provide matching source for any GPL bytes that remain. |

## Other default images

Compose pulls PostgreSQL rather than repackaging it and pulls Redis 7.4.9 by
digest. Normal local use is not image conveyance. Mirroring, exporting, or
shipping those images is a separate distribution act: retain PostgreSQL's
license, and explicitly approve Redis 7.4's RSALv2/SSPLv1 terms before doing so.
The test-only Mailpit image needs the same review only if it is redistributed.

## Release boundary

This lane does not push or export any container image. Source publication is
closed for the owned-provider Git commit once the reviewed branch is pushed:
the image and application both point to the exact fork, and the revision label
pins the bytes to one commit.

Binary distribution is not yet cleared. Before any registry push, image save,
appliance delivery, or offline bundle, the distributor must:

1. generate an image-level SBOM including Debian packages, Python wheels,
   native libraries, and compiled frontend dependencies;
2. bundle all required license texts and copyright notices;
3. archive or make available the exact fork source and matching source for GPL
   and LGPL packages, including the native closure of `psycopg2-binary`;
4. document LGPL relinking/replacement rights and avoid anti-reverse-engineering
   terms that conflict with those rights; and
5. record whether PostgreSQL, Redis, or Mailpit image bytes are included rather
   than merely pulled by the recipient.

Until those five deliverables are attached to a concrete binary artifact,
`distribution-audit` is a packaging/provenance gate, not a legal clearance for
binary conveyance.
