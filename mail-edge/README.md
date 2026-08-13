# SimpleLogin mail edge

`simplelogin-mail-edge` is an independently packaged, provider-neutral durability
boundary for managed inbound mail and managed outbound submission. It owns raw
message handoff, immutable provider-route generations, submission correlation,
feedback normalization, retries, quarantine, and bounded operational metadata.
It does not own aliases, users, mailboxes, contacts, or reverse-alias policy.

The package never imports the SimpleLogin application, `email_handler`, or its
models. Integration is through two neutral wire contracts:

- inbound raw MIME is handed off over an idempotent HTTPS `PUT` with neutral
  `Mail-Edge-*` envelope and correlation headers;
- outbound raw MIME is accepted on the private SMTP spool at port 2525 with a
  UUIDv7 `X-Mail-Edge-Submission-ID` header.

Mailgun is the first production adapter. Managed inbound uses a Mailgun route
whose HTTPS URL ends in `/raw-mime`, causing Mailgun to supply `body-mime`.
Outbound uses authenticated Mailgun SMTP so that the edge can supply the exact
SMTP envelope sender as well as the original MIME. Provider control headers used
for webhook correlation are confined to the adapter and request provider-side
suppression. Activation is blocked until recipient-observed evidence proves the
policy for the exact domain; provider availability or GA status is not evidence.

## Build and install

The release artifacts are a wheel and source distribution produced only from
this directory:

```sh
python3.12 -m build mail-edge
python3.12 -m pip install dist/simplelogin_mail_edge-0.1.0-py3-none-any.whl
```

For reproducible archive timestamps, set `SOURCE_DATE_EPOCH` to the release
commit time. Build twice in clean directories and compare SHA-256 digests.

The included container installs the wheel, runs unprivileged, and has no
SimpleLogin application code or dependency:

```sh
docker build -f mail-edge/Dockerfile mail-edge
```

## State and secrets

Run PostgreSQL with a database and credential owned only by mail-edge. SQLite is
supported for tests and contained evaluation, not multi-process production.
Migrations are packaged under `mail_edge/migrations` and are applied explicitly:

```sh
mail-edge migrate
```

All secrets are file-mounted, must be regular files inaccessible to group/world,
and are read at process start. Required environment variables are:

| Variable | Content or purpose |
| --- | --- |
| `MAIL_EDGE_DATABASE_URL_FILE` | PostgreSQL URL containing the edge-only database credential |
| `MAIL_EDGE_BLOB_ROOT` | Mode-0700 durable local spool volume |
| `MAIL_EDGE_BLOB_KEYS_FILE` | JSON AES-GCM key ring with `active_key_id` and base64 `keys` |
| `MAIL_EDGE_PROVIDER_CREDENTIALS_FILE` | JSON credential sets referenced by immutable bindings |
| `MAIL_EDGE_DIAGNOSTIC_SALT_FILE` | At least 16 random bytes for stable redacted hashes |
| `MAIL_EDGE_HANDOFF_URL` | Product-owned neutral HTTPS ingestion collection URL |
| `MAIL_EDGE_HANDOFF_TOKEN_FILE` | Bearer credential accepted only by that ingestion service |
| `MAIL_EDGE_HOOK_TLS_CERT_FILE` | CA-issued hook certificate chain |
| `MAIL_EDGE_HOOK_TLS_KEY_FILE` | Hook private key |

Blob keys are isolated from the database. Raw MIME and envelopes are AES-GCM
encrypted with per-blob nonces, an authenticated blob identity, atomic no-clobber
writes, file `fsync`, and directory `fsync`. Database rows contain hashes,
sizes, state, and opaque blob keys, not cleartext addresses or message content.

Provider configuration contains only non-secret routing settings and a
`credential_ref`. A Mailgun credential entry contains `smtp_username`,
`smtp_password`, and `webhook_signing_key`. Use a domain-scoped sending
credential and a dedicated Mailgun account or subaccount.

## Processes

Run the processes independently so they can be scaled and restarted by role:

```sh
mail-edge-hook
mail-edge-smtp --host 127.0.0.1 --port 2525
mail-edge-worker --kind ingress
mail-edge-worker --kind outbound
mail-edge-worker --kind retention
mail-edge-metrics
```

The hook starts only with TLS and exposes these provider-specific adapter paths:

- `POST /v1/hooks/mailgun/inbound/{binding-id}/raw-mime`
- `POST /v1/hooks/mailgun/feedback/{binding-id}`

The path pins every event to one immutable binding generation. The adapter
authenticates the Mailgun HMAC and time window, normalizes the request, commits
raw data before returning HTTP 200, and deduplicates retries. Provider-native
payloads never enter neutral contracts or durable diagnostic fields.

The SMTP spool resolves the exact envelope-sender domain during `MAIL FROM`.
Null senders must supply `EDGE=exact.example` as an ESMTP parameter. Unknown
domains receive `550 5.1.8`; there is no default provider or suffix fallback.
After `DATA`, malformed or oversized mail is rejected, while valid mail receives
`250` only after encrypted blob durability and database commit. Reusing the same
submission UUID and bytes is idempotent; reusing it with different bytes or an
envelope is rejected.

The private metrics listener defaults to `127.0.0.1:9090`:

- `/livez` checks the process;
- `/readyz` checks the database, exact packaged migration set, and writable blob
  volume;
- `/metrics` contains only bounded direction/state labels plus unknown and
  quarantine counts.

## Binding activation

Inbound and outbound bindings are independent. Every exact domain and direction
has monotonically increasing, immutable generations. The lifecycle is:

```text
prepared -> shadow -> active -> draining -> disabled
         \-> disabled
```

Create provider configuration in a non-secret JSON file, for example:

```json
{
  "credential_ref": "mailgun-production",
  "smtp_host": "smtp.eu.mailgun.org",
  "smtp_port": 587
}
```

Then create and stage a generation:

```sh
mail-edge binding create --domain aliases.example --direction outbound \
  --provider mailgun --config /secure/outbound-binding.json
mail-edge binding transition BINDING_ID shadow
```

Record durable, reviewed qualification artifacts one capability at a time with
`mail-edge evidence`. Exact-domain evidence is required for routing, DNS,
envelope and MIME fidelity, webhook behavior, retention, feedback, and failure
safety. Account-isolation evidence uses the `*` scope. Evidence expires. The
registry refuses activation if any current product-policy requirement is absent,
failed, expired, scoped to another domain, or unsupported by the installed
adapter.

`mail-edge binding switch CANDIDATE_ID` atomically marks the old active
generation draining and the shadow generation active. Already committed mail
stays pinned to the old generation. A draining generation cannot be disabled
until its nonterminal pinned work count is zero.

## Failure and retention invariants

Workers lease durable work. An expired inbound handoff lease is retried with the
same idempotency key. An expired outbound submission lease is different: the
provider may have accepted the mail, so it becomes `unknown`, is quarantined,
and is never selected by the retry scheduler. A connection loss while awaiting
the provider's post-DATA reply follows the same path. There is no automatic
cross-provider failover.

Inspect and resolve uncertain outcomes with explicit evidence:

```sh
mail-edge unknown list
mail-edge unknown resolve SUBMISSION_ID --accepted \
  --provider-receipt-id RECEIPT --evidence artifact:reconciliation/CASE
mail-edge quarantine
```

Authenticated, correlated feedback can resolve an unknown outcome. Duplicate,
out-of-order, uncorrelated, or conflicting feedback cannot replay product state;
uncorrelated data is quarantined with redacted diagnostics.

Retention deletes encrypted content only after definitive inbound handoff or a
definitive outbound terminal result and expiry. It never automatically deletes
`unknown` or open quarantine content. Deletion unlinks both envelope and MIME
blobs durably before marking the row deleted. Encrypted files left by a crash
before database commit are removed only when no database row references them and
a seven-day orphan grace period has elapsed. Filesystem secure overwrite is not
claimed; cryptographic erasure requires retiring the corresponding isolated
blob key after all blobs encrypted under it have expired and been verified absent.
