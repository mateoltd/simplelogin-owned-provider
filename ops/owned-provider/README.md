# Owned SimpleLogin provider baseline

This directory is the complete local operations layer for the independently
operable SimpleLogin baseline. The application source remains identical to
official upstream commit `dbc45fcce4e8e6b4fa615cc729ca95a67bf75266`.

All published ports bind to loopback. Mailpit is the only outbound SMTP target,
so the test deployment cannot deliver external mail. No DNS changes are needed.

## Requirements

- Docker with Compose
- Git, curl, OpenSSL, Python 3, and `shasum`
- 2 GiB RAM minimum; 4 GiB is preferable on ARM hosts because the pinned image
  runs as `linux/amd64`

## Operate the deployment

```sh
ops/owned-provider/bin/owned-provider init
ops/owned-provider/bin/owned-provider up
ops/owned-provider/bin/owned-provider status
ops/owned-provider/bin/owned-provider e2e
```

`init` generates non-versioned configuration and independent mode-0600 secrets
under `.owned-provider/`. The operator password is never placed in Compose
environment metadata or command arguments. Read it only when interactive access
is required:

```sh
cat .owned-provider/secrets/admin_password
```

The local endpoints are:

- Web and API: `http://127.0.0.1:17777`
- SMTP ingress: `127.0.0.1:20381`
- Mailpit UI and API: `http://127.0.0.1:18025`

Change the ports or local domains in `.owned-provider/config.env`. Secret files
must remain stable across upgrades and restores. Losing the encryption and HMAC
keys can make protected application data or tokens unrecoverable.

## Prove behavior and recovery

The end-to-end test uses the deployed HTTP API, PostgreSQL, Redis, job runner,
SMTP handler, and Mailpit. It covers password login, API keys, mailboxes and
mailbox verification, provisioned local custom-domain use, random and custom
aliases, search and lifecycle operations, contacts and reverse aliases, inbound
forwarding, outbound reply delivery, queue processing, concurrent alias
creation, and an observed HTTP 429.

```sh
ops/owned-provider/bin/owned-provider drill
```

`drill` performs all of the following without mocks:

1. Runs the end-to-end lifecycle.
2. Writes a relationship-complete, secret-free recovery JSON.
3. Creates a checksummed PostgreSQL, upload, Redis, and Mailpit backup.
4. Deletes this deployment's volumes and restores the backup into clean volumes.
5. Compares the canonical alias-relationship hash and performs a new API write.
6. Deletes the volumes again, migrates an empty database, imports the recovery
   JSON, compares the same hash, and performs a new API write.
7. Restores the full backup once more and proves post-restore operation.

Backups and exports remain beneath `.owned-provider/` and are excluded from Git.
Copy them to encrypted, access-controlled storage for real disaster recovery.
Regularly test a copy on a separate host and enforce retention independently.

Individual operations are also available:

```sh
ops/owned-provider/bin/owned-provider export
ops/owned-provider/bin/owned-provider backup
ops/owned-provider/bin/owned-provider restore .owned-provider/backups/BACKUP
ops/owned-provider/bin/owned-provider clean-import .owned-provider/exports/EXPORT.json
ops/owned-provider/bin/owned-provider post-restore
```

The recovery JSON deliberately excludes passwords, API keys, recovery codes,
and encryption keys. It restores the account with the locally held operator
password and recovers every active alias plus its primary and secondary
mailboxes, custom domain, directory, contacts and exact reverse aliases, and
hostname relationships. The full database backup remains the authoritative
method for recovering audit logs, email logs, jobs, historical state, and all
other tables.

## SDK conformance

Run against the SDK laboratory worktree that carries the matching real-service
test. Build output goes under `.owned-provider/sdk-target`; the SDK worktree is
checked clean before and after.

```sh
ops/owned-provider/bin/owned-provider sdk-conformance \
  /absolute/path/to/bitwarden-sdk-internal-simplelogin-lab
```

## Audit and shutdown

```sh
ops/owned-provider/bin/owned-provider audit
ops/owned-provider/bin/owned-provider logs
ops/owned-provider/bin/owned-provider down
```

`audit` verifies the source ancestry and image revision, operations-only diff,
mode-0600 secrets, absence of secret values from Docker metadata, loopback port
bindings, non-root application processes, read-only root filesystems, dropped
capabilities, dependency health, and migration head.

`down` retains data. `destroy` removes only the four explicitly named volumes
owned by this deployment and is intended for recovery drills or disposal.

See [PRODUCTION_AUDIT.md](PRODUCTION_AUDIT.md) before using this baseline outside
the local containment boundary and [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md) before
adopting another upstream commit.
