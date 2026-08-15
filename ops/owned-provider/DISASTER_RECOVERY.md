# Disaster recovery runbook

## State boundary

The deployment owns PostgreSQL, including all four Mail Edge host projection
tables, Redis AOF/RDB state, uploads, the unsent-mail spool, the rendered Mail
Edge configuration, and every mounted service secret. The contained test also
owns Mailpit state. The unlinked raw callback spool is ephemeral and is
recreated empty. Production MTA queues, the external Mail Edge PostgreSQL and
object store, monitoring, and secrets-manager history are separate components
and need coordinated native backup policies; this overlay must not pretend to
own or restore them.

## Deterministic full-state checkpoint

```sh
ops/owned-provider/bin/owned-provider export /secure/checkpoints/provider-state
ops/owned-provider/bin/owned-provider import /secure/checkpoints/provider-state
```

Export briefly quiesces all writers, forces Redis persistence, takes a
PostgreSQL consistent dump, and archives every owned volume with sorted paths,
normalized timestamps, owners, and PAX metadata. `MANIFEST` records the pin,
schema, checkpoint time, components, rendered Mail Edge config digest, and a
deterministic semantic SHA-256 over every row and sequence in every `public`
and `owned_provider` table. That includes replay nonces, callback receipts and
fences, outbound projections, and route binding generations. Import
checks every file hash, restores into clean volumes, compares the full database
semantic digest, runs migrations idempotently, and requires readiness.

The plaintext export contains provider data and must remain in access-
controlled temporary storage. Prefer encrypted backups for retention.

## Encrypted backup

```sh
ops/owned-provider/bin/owned-provider backup /backups/provider-UTC.opb
```

The CLI packages the full checkpoint, environment configuration, rendered Mail
Edge configuration, a checksummed control manifest, and all runtime secrets
except the backup key, then streams AES-256-GCM authenticated encryption to a
temporary file and atomically renames it. Restore verifies both configuration
digests and the exact secret-name inventory before copying any control state. A
SHA-256 sidecar detects transport damage before decryption. Copy both files
off-host, enforce immutable retention, and escrow `backup_encryption_key`
separately.

The importer also accepts the immediately preceding state format 2 and its
manifest-less control archive. That upgrade path verifies the legacy database
digest before running migrations, requires that the four Mail Edge host tables
are absent, generates fresh provider-neutral Mail Edge secrets and a disabled
default host configuration, and then creates the new tables through the normal
migration chain. State format 3 remains strict: its saved host configuration
digest and exact control secret inventory must match. Older formats require a
restore through their original release first; they are not guessed or coerced.

## Clean-machine restore

1. Checkout this fork at the backup's recorded lineage and build the pinned
   image. Do not start an empty provider publicly.
2. Create an empty mode-0700 runtime and place only the escrowed
   `secrets/backup_encryption_key` in it with mode 0600.
3. Run:

   ```sh
   OWNED_PROVIDER_RUNTIME_DIR=/restore/runtime \
     ops/owned-provider/bin/owned-provider restore /backups/provider-UTC.opb
   ```

4. Confirm manifest hashes, semantic database digest, migrations, readiness,
   and the alertable synthetic result. In an isolated contained environment,
   run `post-restore` to prove authenticated API create/delete, inbound
   forwarding, and reverse reply. With Mail Edge enabled, the same path must
   additionally observe signed recipient/delivery callbacks, raw-grant
   consumption, outbound intent creation, and new edge workflow state. In a
   production-shaped environment, use
   controlled external sender/recipient mailboxes and observe the production
   MTA rather than the contained-only command.
5. Run DNS/MTA checks for the restored host before moving traffic.

`drill` automates this with empty volumes and a newly initialized runtime. It
writes checkpoint markers to PostgreSQL, Redis, uploads, the unsent spool, and
the contained mail store, creates later markers, restores, proves checkpoint
markers present and later markers absent, recreates the empty Mail Edge spool,
and resumes API plus both mail directions. It also round-trips representative
rows from all four Mail Edge host tables, then runs signed recipient, delivery,
reverse-route, and feedback callbacks through a real local HTTP socket. The
delivery consumes a scoped raw grant once, repeats the delivery ID without a
second business effect, records outbound/feedback state, rejects a replayed
signature, and proves the file-backed spool is empty after cleanup. The
test-only edge peer is bounded and isolated; the separate exact-contract gate
exercises the real Mail Edge reference service. Drill evidence names the Mail
Edge projections, configuration, secrets, and callback outcomes explicitly.
This is a genuine point-in-time assertion, not merely a container health check.

An external Mail Edge restore is a coordinated but independent operation:
restore its PostgreSQL, exact object versions, KMS/secret access, and provider
configuration using that product's runbook; quarantine every `dispatching`
attempt at the recovery cut; then start this host against the restored edge and
exercise callbacks before moving traffic. Never resend an uncertain attempt.

Set backup frequency from business RPO, rehearse restore at least quarterly,
and measure RTO on production-shaped data. A backup is not complete until an
isolated restore has passed.
