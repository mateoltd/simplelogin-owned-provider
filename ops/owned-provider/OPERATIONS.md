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
PostgreSQL, Redis, upstream Alembic head, and no taken job older than the retry
window. `/metrics` is Prometheus text format with bounded labels for dependency
state, objects, jobs, synthetic freshness, backup freshness, database/Redis
size, connections, and volume capacity.

Load `alerts.yml` into Prometheus-compatible alerting and route its critical
alerts to an attended pager. Tune the storage and backup thresholds to the
deployment RPO and measured growth; do not remove freshness alerts.

## Structured logs

Application, SMTP, mail-feedback, job-runner, observer, and synthetic output is one JSON
object per bounded line. Known environment and mounted-file secret values are
replaced, authorization-like fields are redacted, and email addresses/IPs are
deterministically pseudonymized. Collect stdout/stderr with a restricted log
pipeline and enforce retention. Treat logs as sensitive even after redaction.

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

## Mail-edge core bridge

The private service on `mail-feedback:7781` accepts only HMAC-authenticated
neutral records. It deduplicates feedback event IDs, persists replay nonces,
accepts feedback before message correlation, and applies pending hard-bounce or
complaint outcomes when the mapping arrives. `GET /v1/ingress/{ingress_id}`
lets the edge reconcile an SMTP DATA acknowledgement loss without resending an
ambiguous delivery.

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

## Incident order

1. Check `/readyz`, alert labels, dependency health, free storage, and job age.
2. Preserve structured logs and a database snapshot before manual repair.
3. Stop only the failing ingress/worker when continued work increases harm.
4. Fix dependencies, then run `probe`, `reconcile`, and a controlled mail test.
5. Restore only when data corruption or loss is established; follow the DR
   runbook and preserve the failed volumes for analysis.
