# Capacity and safeguards

Alias count is not capped by this overlay. The operator account is premium and
the upstream database schema has indexed alias ownership, email, full-text note
search, custom domains, mailboxes, contacts, and queue selection.

Bounded safeguards protect finite resources instead:

- configurable API creation rate windows and endpoint limits;
- 25 MiB default SMTP message limit;
- Gunicorn worker count, request recycling, timeout, and jitter;
- per-container memory, CPU, PID, and file-descriptor limits;
- PostgreSQL connection/shared-buffer limits and slow-query logging;
- Redis `noeviction` with a fixed memory ceiling so locks/rate limits fail
  visibly instead of silently evicting;
- persistent unsent-mail spool and database-backed job retries;
- bounded API responses, mail-sink retention, probe retention, and worker batch;
- free-storage, queue-age, dependency, synthetic, and backup alerts.

Mail-edge adds independent finite resources and limits:

- a configurable raw SMTP and inbound-hook limit, defaulting to 25 MiB before
  form-encoding overhead, with no truncation or attachment rewriting;
- bounded SMTP recipients, command/header sizes, webhook fields and age,
  diagnostics, worker leases, retry attempts, backoff, and queue batches;
- PostgreSQL connections and write rate for dedupe, leases, feedback, evidence,
  and route state;
- encrypted blob bytes for ready/retry mail plus deliberately retained unknown
  and quarantine content;
- hook, SMTP-spool, ingress-worker, outbound-worker, and retention-worker
  concurrency;
- provider account/domain recipient rate, accepted-message quota, webhook retry
  window, event delay, retention, and suppression growth.

Size local blob capacity for peak accepted ingress plus outbound intake during
the longest downstream/provider outage, retry backlog, backup overlap, and an
explicit unknown/quarantine reserve. Unknown work is not a retry queue and must
not be aged out automatically to recover capacity. Storage alerts must fire
before the SMTP spool loses its ability to make a durable commit; at that point
SMTP returns a temporary failure rather than `250`.

Provider quota is a ceiling, not throughput evidence. A Mailgun plan or GA
status never activates a binding. Qualification must measure the exact account,
region, domain, MIME-size distribution, envelope behavior, feedback lag, and
controlled recipient delivery. There is no automatic provider failover to turn
quota exhaustion into duplicate delivery.

Run the repeatable production-shaped profile with a configurable count:

```sh
ops/owned-provider/bin/owned-provider load 10000
```

The command refuses counts below 10,000 because that is the acceptance floor,
deletes only its `capacity-*` fixture rows, inserts in 1,000-row transactions,
then measures authenticated paginated list and indexed search p50/p95 latency.
Fixture domains come from contained RFC-reserved example configuration. Record
host CPU/RAM, database size, results, and revision together. Increase the count
to model forecast growth; never convert the test floor into a production cap.

Run a separate mail-edge profile against an isolated database, blob volume,
provider test domain, and controlled recipients. Measure ingress durable-commit
latency, SMTP post-DATA commit latency, worker throughput, oldest ready/retry
age, feedback lag, blob growth/deletion, restart recovery, and the effect of a
provider throttle. Include duplicate and out-of-order webhooks and a bounded
rate of forced unknown outcomes. Do not use production domains or recipients for
capacity generation.
