# Mail Edge qualification verification

The independently versioned Mail Edge source is pinned by
`MAIL_EDGE_CONTRACT_COMMIT` to
`698eb3c835ac1fd6dcc5b5ced1ac86ecfb0d1d4e`. This is the executable source pin;
the host does not copy the edge implementation or select a provider.

`MAIL_EDGE_EVIDENCE_COMMIT` separately pins the evidence-only child
`b828793a41cacf8a214ae94423422e9c27bf1af2`. The gate requires that commit's
only changes to be the eight canonical W9 evidence paths, verifies that its
parent is the source pin, extracts the files without modifying either
repository, checks artifact and canonical payload digests, and verifies the
Ed25519 signature using the source commit's own verifier.

From a clean Mail Edge checkout at the source pin, with Node 24.19.0, pnpm
11.21.0, Docker, and this fork's `.venv` prepared, run:

```sh
ops/owned-provider/bin/owned-provider mail-edge-contract-check /path/to/mail-edge
```

The command installs only the frozen Mail Edge lockfile and runs:

- W9 evidence build, canonical audit, and signature verification;
- the direct Mail Edge-to-SimpleLogin signature/replay interoperability test;
- W2 integration and the real PostgreSQL/MinIO/queue reference-service E2E;
- the reference-service OCI and reproducibility gate; and
- the complete Mail Edge repository verification suite, including boundaries,
  schemas, migrations, package/API drift, licenses, SBOM, secret policy, and
  hostile provider fault cases.

Full output is written beneath the private runtime evidence directory and only
its tail is printed. Any gate failure is retained honestly and makes the
command fail; no upstream test is skipped, patched, or replaced locally.

The signed W9 payload itself reports `limited`, not `qualified`. Its explicit
remaining blockers are independent security/architecture review, a forbidden
and therefore unperformed live-provider qualification, and the unperformed
exact Section 16.7 sustained 8-vCPU/16-GiB/46.08-GB workload. The evidence is
canonical proof of what ran, not authorization to deploy, mutate DNS, create a
provider account, or claim those external blockers are complete.
