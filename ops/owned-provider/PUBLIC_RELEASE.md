# Public-release compliance bundle

This lane produces a deterministic, reviewable engineering bundle for one
exact owned-provider source commit, one exact Mail Edge source pin, and one
locally inspected owned-provider OCI image. It is independent of Crimson and
does not run or claim Section 16.7.

The current reviewed baseline is:

- integration base `1a236e00bc63e4125c4d175607b37f7f1e2061e6` on
  `integration/owned-provider-qualified-mail-edge`;
- release branch `fix/owned-provider-compliance-bundle`;
- current qualified Mail Edge source pin
  `698eb3c835ac1fd6dcc5b5ced1ac86ecfb0d1d4e`; and
- signed Mail Edge evidence status `limited`, as recorded by
  `MAIL_EDGE_EVIDENCE_COMMIT` and `public-release-policy.toml`.

The source pin and the evidence status are separate facts. The current source
pin is the input to this bundle. The limited evidence does not prove Section
16.7, external review, provider qualification, signatures, or legal approval.

## Scope

The generated archive conveys the exact owned-provider and Mail Edge Git source
archives, dependency source materials selected by policy, licenses, notices,
SBOMs, and build evidence. It does not contain an OCI image. The inspected
owned-provider image is evidence-bound by image ID, rootfs diff IDs, OCI labels,
runtime inventories, native hashes, and resolved shared-library edges.

PostgreSQL, Redis, Mailpit, the Mail Edge OCI image, credentials, account state,
and DNS state are not conveyed. If any of those bytes are later included, the
distribution scope and review must change before generation can pass.

## Reviewed dependency closure

For the current pins, generation resolves and inspects:

| Graph | Records | Runtime or production closure | Source of identity |
| --- | ---: | ---: | --- |
| owned-provider Python | 115 | 115 | `uv.lock` plus `runtime-python.txt` |
| owned-provider frontend npm | 39 | 39 | production reachability in `static/package-lock.json` |
| Mail Edge pnpm | 951 | 191 | every package and snapshot plus importer reachability in the pinned `pnpm-lock.yaml` |
| reviewed vendored npm | 4 | 4 | exact registry URL and SRI in `public-release-policy.toml` |
| project roots | 2 | 2 | exact live Git commits and tree provenance |

Mail Edge counts are recorded results, not fixed acceptance criteria. A later
advertised pin may change them. The parser still fails closed unless every
snapshot has exact package metadata, integrity, dependency edges, license
evidence, and an unambiguous source mapping.

License conclusions come from the exact package archive metadata and license
files. Exact package-and-version overrides are allowed only in the reviewed
policy. The generator downloads every package archive and verifies its lockfile
hash or integrity before using metadata. It includes every discovered package
license or notice, standard SPDX texts, all owned-provider runtime sources, all
vendored sources, and any dependency source archive whose resolved license is
copyleft.

Non-standard terms are represented with package-specific SPDX `LicenseRef`
identifiers. Their reviewed text must occur byte-for-byte in the exact package
license evidence, is copied to `licenses/custom`, and is embedded as SPDX
extracted licensing information. The current references cover psycopg2's
OpenSSL linking exception and PyCryptodome's public-domain grant; neither is
misrepresented as a standard SPDX exception or license.

## Static assets

`dependencies/static-assets.json` is generated and semantically verified
against the owned-provider source archive. The current review requires:

- 477 `static/assets` files byte-identical to `tabler-ui@0.0.34`;
- one fork-modified Tabler file, `static/assets/js/core.js`;
- three reviewed local-only assets, including the two Duo browser helpers;
- `static/vendor/clipboard.min.js` byte-identical to `clipboard@2.0.4`;
- readable Bootstrap Social source with the historical minifier recorded as
  unknown; and
- readable jVectorMap 2.0.3 source, with the non-byte-identical local minified
  relationship explicitly recorded as uncertain.

The unlicensed local Paddle fallback was removed. Paddle.js is loaded directly
from Paddle's documented CDN and is not part of the repository source archive.

## Obligation boundary

This is an engineering assessment, not legal approval.

| Conveyed material | Engineering obligation and implemented evidence |
| --- | --- |
| owned-provider AGPL source | Exact source archive, Git provenance, AGPL text, build and operations inputs, and source route remain present. |
| Mail Edge Apache source | Exact pinned source archive, Git provenance, Apache text, frozen lock and workspace build inputs. |
| GPL, AGPL, LGPL, MPL, EPL, or CDDL package source copied into the bundle | Exact verified package archive, resolved expression, package notices, standard license text, dependency edges, and source mapping. |
| JavaScript and CSS served from owned-provider | Exact lock or reviewed vendored mapping, source archive, license evidence, and static-asset relationship audit. |
| owned-provider OCI image | Inspected only. No image bytes are in this public-release archive. Binary conveyance remains blocked unless the separate image-bound `distribution_bundle.py` pipeline passes for the exact image. |
| dynamically linked or interpreted LGPL software in a later conveyed image | Preserve notices, matching source, replacement rights, native linkage evidence, and installation instructions. The image-bound pipeline must determine the exact materials. |
| statically linked LGPL Combined Work in a later conveyed image | Provide the relinkable application object or link inputs and instructions required for the exact artifact. No such Combined Work is conveyed by this source-only archive. |

The presence of LGPL source code in this source archive does not itself create
a Combined Work binary. Relinkable object files are therefore not fabricated.
The separate binary gate remains mandatory if image bytes are ever exported,
pushed, mirrored, or delivered.

## Generation and verification

Run from the exact clean release checkout after its HEAD is advertised by the
live origin. Build the exact image first. Keep all output and cache paths outside
Git:

```sh
source_sha="$(git rev-parse HEAD)"
mail_edge_sha="698eb3c835ac1fd6dcc5b5ced1ac86ecfb0d1d4e"
artifact_root="../.artifacts/owned-provider-compliance"

python3 ops/owned-provider/scripts/public_release_bundle.py generate \
  --repository "$PWD" \
  --mail-edge-repository ../mail-edge \
  --mail-edge-commit "$mail_edge_sha" \
  --image "simplelogin-owned-provider:$source_sha" \
  --cache "$artifact_root/cache" \
  --output "$artifact_root/bundle-a"

python3 ops/owned-provider/scripts/public_release_bundle.py generate \
  --repository "$PWD" \
  --mail-edge-repository ../mail-edge \
  --mail-edge-commit "$mail_edge_sha" \
  --image "simplelogin-owned-provider:$source_sha" \
  --cache "$artifact_root/cache" \
  --output "$artifact_root/bundle-b"

diff -ru "$artifact_root/bundle-a" "$artifact_root/bundle-b"
cmp "$artifact_root/bundle-a.tar.gz" "$artifact_root/bundle-b.tar.gz"
```

The generator refuses a dirty or wrong checkout, origin drift, live branch
drift, an unadvertised Mail Edge commit, stale locks, unsafe archives,
ambiguous or mismatched licenses, missing source or notice material, incomplete
container scans, mismatched runtime closures, noncanonical JSON, and checksum or
SBOM disagreement. Rewriting `SHA256SUMS` cannot bypass the semantic verifier.

The secret gate uses the Gitleaks 8.30.1 default rules. Its reviewed macOS arm64
release archive SHA-256 is
`b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`.
Seven public test fixture or example paths are allowlisted because the upstream
tree intentionally contains test private keys and token-shaped examples. Every
complete file is SHA-256-pinned in `public-release-policy.toml`; a byte change
fails before the allowlisted scan runs:

```sh
python3 ops/owned-provider/scripts/public_release_bundle.py secret-scan \
  --repository "$PWD" --gitleaks /reviewed/path/to/gitleaks
```

## Final Mail Edge pin

After the final commit is advertised by the Mail Edge live origin, substitute
only the command argument:

```sh
python3 ops/owned-provider/scripts/public_release_bundle.py generate \
  --repository "$PWD" \
  --mail-edge-repository ../mail-edge \
  --mail-edge-commit FINAL_MAIL_EDGE_SHA \
  --image "simplelogin-owned-provider:$(git rev-parse HEAD)" \
  --cache ../.artifacts/owned-provider-compliance/cache \
  --output ../.artifacts/owned-provider-compliance/final-pin-bundle
```

No source edit is required. This command regenerates evidence for the supplied
pin; it does not upgrade the limited signed evidence or claim that Section 16.7
has completed.
