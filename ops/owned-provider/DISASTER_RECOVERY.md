# Disaster recovery runbook

## State boundary

The deployment owns PostgreSQL, Redis AOF/RDB state, uploads, the unsent-mail
spool, configuration, and secrets. The contained test also owns Mailpit state.
Production MTA queues, object storage, monitoring, and secrets-manager history
are external components and need coordinated native backup policies.

The independently deployed mail-edge is also outside this overlay's checkpoint
and encrypted backup. It owns a separate PostgreSQL database, encrypted blob
volume, blob key ring, provider credential file, diagnostic salt, handoff token,
TLS private key, migration history, route generations, evidence, feedback,
unknown outcomes, and quarantine. None is included by `owned-provider backup`.
Treat omission as data loss, not as a stateless service rebuild.

## Mail-edge recovery set

Back up the edge database and encrypted blob volume at a mutually consistent
checkpoint. Escrow blob keys separately from both. Back up provider and handoff
credentials through the secrets manager rather than copying them into the data
archive. Preserve capability artifacts at their recorded durable URIs and verify
their SHA-256 values.

Restore mail-edge in this order:

1. Restore the edge database and encrypted blob volume to an isolated network at
   the recorded release SHA. Restore blob keys and other credentials from their
   separate escrow.
2. Run packaged edge migrations and verify exact migration parity, database
   constraints, blob authentication/hashes, route-generation immutability, and
   the absence of orphaned cleartext.
3. Start only hook and metrics. Keep SMTP intake and both workers stopped while
   inspecting leases, unknown outcomes, quarantine, provider webhook backlog,
   and route states.
4. Convert every outbound `submitting` lease that crossed the checkpoint or has
   uncertain provider timing to `unknown`; the normal lease recovery performs
   this conservatively. Never reset it to queued.
5. Start ingress handoff and prove idempotent recovery with controlled fixtures.
   Then start outbound only after unknown records are isolated and the pinned
   provider generation is available.
6. Reconcile controlled external delivery/feedback and confirm storage,
   unknown, quarantine, and feedback-lag metrics before accepting SMTP or
   changing DNS.

Database-only restore is insufficient because rows reference encrypted blobs.
Blob-only restore is insufficient because it lacks dedupe, generation, and
outcome state. Restoring an older database with newer blobs may leave safe
orphans, but restoring newer rows without their blobs loses accepted mail.

## Deterministic full-state checkpoint

```sh
ops/owned-provider/bin/owned-provider export /secure/checkpoints/provider-state
ops/owned-provider/bin/owned-provider import /secure/checkpoints/provider-state
```

Export briefly quiesces all writers, forces Redis persistence, takes a
PostgreSQL consistent dump, and archives every owned volume with sorted paths,
normalized timestamps, owners, and PAX metadata. `MANIFEST` records the pin,
schema, checkpoint time, components, and a deterministic semantic SHA-256 over
every row and sequence in every `public` and `owned_provider` table. Import
checks every file hash, restores into clean volumes, compares the full database
semantic digest, runs migrations idempotently, and requires readiness.

The plaintext export contains provider data and must remain in access-
controlled temporary storage. Prefer encrypted backups for retention.

## Encrypted backup

```sh
ops/owned-provider/bin/owned-provider backup /backups/provider-UTC.opb
```

The CLI packages the full checkpoint plus configuration and all runtime secrets
except the backup key, then streams AES-256-GCM authenticated encryption to a
temporary file and atomically renames it. A SHA-256 sidecar detects transport
damage before decryption. Copy both files off-host, enforce immutable retention,
and escrow `backup_encryption_key` separately.

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
   forwarding, and reverse reply. In a production-shaped environment, use
   controlled external sender/recipient mailboxes and observe the production
   MTA rather than the contained-only command.
5. Run DNS/MTA checks for the restored host before moving traffic.

`drill` automates this with empty volumes and a newly initialized runtime. It
writes checkpoint markers to PostgreSQL, Redis, uploads, the unsent spool, and
the contained mail store, creates later markers, restores, proves checkpoint
markers present and later markers absent, and resumes API plus both mail directions.
This is a genuine point-in-time assertion, not merely a container health check.

Set backup frequency from business RPO, rehearse restore at least quarterly,
and measure RTO on production-shaped data. A backup is not complete until an
isolated restore has passed. The owned-provider and mail-edge restore drills are
separate required proofs until an external orchestrator demonstrates their
coordinated checkpoint and recovery.
