# Operations runbook

## Start and verify

```sh
ops/owned-provider/bin/owned-provider production-audit
ops/owned-provider/bin/owned-provider up
ops/owned-provider/bin/owned-provider status
ops/owned-provider/bin/owned-provider probe
ops/owned-provider/bin/owned-provider reconcile
```

`/livez` proves the observer process is alive. `/readyz` requires the API,
PostgreSQL, Redis, upstream Alembic head, no taken job older than the retry
window, and, when enabled, `/health/mail-edge/readyz`. The application Mail Edge
probe checks PostgreSQL, the external edge, writable spool headroom, and enough
live per-worker RSS capacity for one maximum-size delivery. A provider outage
is dependency degradation, not process liveness, so SMTP and worker containers
retain process-only health checks and avoid restart storms. `/metrics` uses
bounded labels and includes the four local Mail Edge projection tables,
unfinished callbacks, quarantined outbound projections, and spool free space
without tenant, domain, address, message, or workflow identifiers.

Load `alerts.yml` into Prometheus-compatible alerting and route its critical
alerts to an attended pager. Tune the storage and backup thresholds to the
deployment RPO and measured growth; do not remove freshness alerts.

## Structured logs

Application, SMTP, job-runner, observer, and synthetic output is one JSON
object per bounded line. Known environment and mounted-file secret values are
replaced, authorization-like fields are redacted, and email addresses/IPs are
deterministically pseudonymized. Collect stdout/stderr with a restricted log
pipeline and enforce retention. Treat logs as sensitive even after redaction.
The audit scans recent container output for every mounted secret value; Mail
Edge callback logs contain only stable operation, status, duration, and safe
error codes.

```sh
ops/owned-provider/bin/owned-provider logs
```

## Queue semantics

The upstream database queue atomically takes work, reclaims stale work after 30
minutes, retries up to five attempts, and indexes the take query. Provider jobs
used by the synthetic and export tests suppress duplicate ready events. The
contained `queue-drill` removes the SMTP sink, proves a failed taken attempt,
ages it past the retry boundary, restores SMTP, and proves completion on the
second attempt.

Terminal job errors require payload-specific review before requeue. Never mass
reset jobs without confirming the handler is idempotent and the underlying
failure is fixed.

## Lifecycle and reconciliation

```sh
ops/owned-provider/bin/owned-provider lifecycle status
ops/owned-provider/bin/owned-provider lifecycle mailbox-disable user@example.net
ops/owned-provider/bin/owned-provider lifecycle mailbox-enable user@example.net
ops/owned-provider/bin/owned-provider reconcile
```

Lifecycle writes use stable operation keys and always reassert the requested
state, including after an intervening opposite action. Reconciliation checks
ownership across alias-primary mailbox,
alias-secondary mailbox, contacts, custom domains, configured alias domains,
and custom-domain email suffixes using database-side aggregates.

Mail Edge binding transitions and quarantine decisions are separate privileged
control-plane operations exposed by the host bridge. They remain fenced and
audited by the external edge. Never use an SMTP fallback after an ambiguous
Mail Edge dispatch or callback; inspect the durable intent/delivery ID and use
the exact edge reconciliation workflow.

```sh
ops/owned-provider/bin/owned-provider mail-edge-lifecycle binding-inspect ID VERSION
ops/owned-provider/bin/owned-provider mail-edge-lifecycle outbound-inspect INTENT_ID
ops/owned-provider/bin/owned-provider mail-edge-lifecycle inbound-inspect RECEIPT_ID
```

Transition and decision subcommands require expected versions/fences, a bounded
reason code, and allowlisted JSON evidence. `authorize_retry` automatically uses
the distinct privileged credential and remains an explicit duplicate-delivery
risk; no bulk or implicit retry command exists.

## Shutdown and restart

Application roles receive a 45-second Compose grace. Gunicorn workers and the
SMTP controller stop accepting new work, the SMTP controller closes, and each
process-owned Mail Edge bridge rejects new operations and drains active HTTP or
raw downloads for at most its configured `shutdownSeconds`. A stale callback
that crossed the local business-effect fence remains ambiguous by design and is
not replayed as a fresh delivery. `restart-drill` proves clean process restart;
the full drill additionally proves restored callback journals and projections.
`OWNED_PROVIDER_GUNICORN_TIMEOUT_SECONDS` defaults to 90 so a cold worker can
finish importing the pinned application under the supported amd64 image. It is
a worker liveness ceiling, not the Mail Edge HTTP or MIME deadline, and the
45-second container stop grace remains the shutdown bound.

## Contract qualification

`MAIL_EDGE_CONTRACT_COMMIT` pins the independently versioned reference-service
contract qualified by this host. From a clean checkout at that exact SHA, run:

```sh
ops/owned-provider/bin/owned-provider mail-edge-contract-check /path/to/mail-edge
```

The command refuses a dirty or different worktree, builds the reference service,
and runs its real PostgreSQL/MinIO/provider-protocol E2E suite. It stores full
output as evidence and prints only the tail. This is a compatibility gate, not
permission to merge, deploy, activate a provider, or mutate DNS.

## Incident order

1. Check `/readyz`, alert labels, dependency health, free storage, and job age.
2. Preserve structured logs and a database snapshot before manual repair.
3. Stop only the failing ingress/worker when continued work increases harm.
4. Fix dependencies, then run `probe`, `reconcile`, and a controlled mail test.
5. Restore only when data corruption or loss is established; follow the DR
   runbook and preserve the failed volumes for analysis.
