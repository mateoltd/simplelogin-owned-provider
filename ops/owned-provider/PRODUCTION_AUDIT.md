# Production readiness audit

## Implemented controls

- **Provenance:** the image embeds the full official upstream Git revision, and
  the branch records it in `UPSTREAM_COMMIT`.
- **Isolation:** all local modifications live in `ops/owned-provider/` except a
  single runtime ignore rule. No SimpleLogin application or migration file is
  patched.
- **Secrets:** independent random values are generated for PostgreSQL, Flask,
  VERP, transfers, recovery codes, partner tokens, encryption, MAC, and abuse
  derivation. Compose mounts files instead of embedding values in container
  metadata. Host permissions are checked as `0600`.
- **Admin access:** registration is closed, the single operator is explicitly
  bootstrapped and premium, the API issues revocable per-device keys, and web,
  API, SMTP, and sink ports bind only to loopback.
- **Database:** PostgreSQL uses a pinned image, health checks, a persistent
  volume, official Alembic migrations, and a migration-head assertion.
- **Queue:** the real persistent database-backed job runner is supervised by
  Compose. The end-to-end test queues and observes completion of a user-data
  export job. Redis uses AOF for sessions, distributed locks, and rate limits.
- **Mail state:** the real SimpleLogin SMTP handler receives inbound and
  reverse-alias traffic. Local outbound delivery terminates at persistent
  Mailpit. Email logs are retained in PostgreSQL; sink, Redis, and upload state
  are included in the backup.
- **Observability:** service health checks, stdout/stderr logs, migration state,
  dependency checks, queue-state counts, and mail-state counts are available
  through `status` and `logs`.
- **Disaster recovery:** checksummed backup and clean-volume restore are
  automated. The portable export has an integrity hash and a clean-database
  importer that verifies the recovered relationship graph.
- **Runtime hardening:** app, email handler, job runner, and tools run as UID/GID
  65532 with read-only root filesystems, a bounded temporary filesystem, all
  Linux capabilities dropped, and `no-new-privileges`.

## Genuine blockers before public production

These require deployment-specific authority or infrastructure and are
intentionally not fabricated by the local baseline:

1. A controlled domain with correct MX, SPF, DKIM, DMARC, and reverse DNS.
2. A production MTA with authenticated outbound relay, queue monitoring,
   reputation management, bounce handling, and abuse controls. Mailpit must not
   be used as a production relay.
3. A TLS reverse proxy, a trusted certificate, hardened forwarded-header policy,
   and an explicit public firewall/load-balancer configuration.
4. Off-host encrypted backups with retention, restore-host capacity, access
   logging, and tested key escrow. Local backups alone do not survive host loss.
5. External monitoring and alert delivery for HTTP, PostgreSQL, Redis, job
   backlog/errors, SMTP queue/deferred mail, disk, certificate expiry, and
   backup freshness.
6. High-availability and capacity decisions for PostgreSQL, Redis, SMTP ingress,
   workers, and the web tier, including regional failure objectives and measured
   RPO/RTO.
7. A security and privacy review covering admin MFA policy, data retention,
   log redaction, vulnerability scanning, dependency updates, abuse response,
   and applicable legal obligations.
8. Replacement of local `.lan` identities and loopback URLs, followed by a full
   staging drill using the real production topology without delivering mail to
   uninvolved recipients.

The baseline is production-capable in software and operations, but it is not a
claim that the unconfigured external mail and network dependencies are ready.
