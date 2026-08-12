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
