# Disaster recovery runbook

## State boundary

The deployment owns PostgreSQL, Redis AOF/RDB state, uploads, the unsent-mail
spool, configuration, and secrets. The contained test also owns Mailpit state.
Production MTA queues, object storage, monitoring, and secrets-manager history
are external components and need coordinated native backup policies.

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
isolated restore has passed.
