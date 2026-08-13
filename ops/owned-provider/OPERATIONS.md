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

Mail-edge is a separate service and is not covered by the commands or readiness
above. Its independent start order is migration, TLS hook, SMTP spool, ingress
worker, outbound worker, retention worker, and metrics. Verify its `/readyz` and
bounded `/metrics` before any binding or DNS activation. A ready process proves
only database migration parity and local dependencies, not provider
qualification.

## Structured logs

Application, SMTP, job-runner, observer, and synthetic output is one JSON
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

Terminal job errors require payload-specific review before requeue. Never mass
reset jobs without confirming the handler is idempotent and the underlying
failure is fixed.

Mail-edge has different reducers and must not be operated through the upstream
job table. Inbound handoff leases may retry with the same edge idempotency key.
Outbound work may retry only after a failure known to precede provider
submission. An expired outbound `submitting` lease, worker crash while awaiting
post-DATA acknowledgement, timeout, or disconnect becomes `unknown`. It is
removed from scheduling and never automatically resent or moved to another
provider.

```sh
mail-edge status
mail-edge unknown list
mail-edge quarantine
```

Resolve unknown work only from authenticated provider feedback or a reviewed
provider query/artifact:

```sh
mail-edge unknown resolve SUBMISSION_ID --accepted \
  --provider-receipt-id RECEIPT --evidence artifact:incident/CASE
```

The alternative `--rejected` conclusion requires equally explicit evidence.
Do not infer rejection from silence. Preserve the original generation and
encrypted blob until resolution.

## Mail-edge route operations

New exact-domain work selects only an `active` generation. Switches are atomic
and direction-specific; already committed work remains pinned.

```sh
mail-edge binding show BINDING_ID
mail-edge binding transition BINDING_ID shadow
mail-edge binding switch CANDIDATE_ID
```

The switch command refuses an unqualified candidate. A draining generation
cannot be disabled while nonterminal pinned work exists. Never edit a generation
or its provider configuration in place; create the next generation, qualify it,
switch, observe, drain, and disable.

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

For mail-edge incidents, also freeze route switches, preserve the edge database
and encrypted blobs, inspect unknown/quarantine before restarting outbound
workers, and determine whether any lease crossed provider DATA. Keep inbound and
outbound decisions independent. A provider incident is not authority for
automatic cross-provider failover.
