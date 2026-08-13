# Mail-edge conformance package

This package qualifies a mail-edge adapter from observed behavior. It contains
no production relay, provider activation, DNS mutation, deployment path, or
alias-state migration. Provider documentation can guide an adapter, but it is
never capability evidence.

## Contract

Every adapter implements `SubmissionAdapter` and receives only the neutral
`DeliveryRequest` fields: edge delivery ID, SMTP envelope, complete RFC 822
bytes, SMTPUTF8 requirement, and SMTP options. It returns `accepted`, `retry`,
`reject`, or `unknown`. Provider response formats and event names stay in the
provider module.

`compare_messages` parses the submitted and received messages and compares:

- ordered MIME topology and non-boundary content parameters;
- every decoded leaf-body hash and size;
- attachment filename, media type, size, and SHA-256;
- the HTML `cid:` reference graph and referenced part paths;
- visible `From`, `Reply-To`, `To`, `Cc`, and `Subject` values;
- `Message-ID`, `In-Reply-To`, and `References`; and
- all other ordered, unfolded headers, including duplicates.

Only exact header names in `TransportHeaderPolicy` may differ. Wildcards are
rejected. The default list contains standard receipt, authentication, ARC, and
DKIM transport fields. `Date` and `Message-ID` are not defaults. Adding a
visible identity header to the transport list does not bypass the separate
identity comparison.

## Corpus and failure matrix

`corpus/manifest.json` pins every real EML by SHA-256. Fourteen committed cases
cover nested alternative/related MIME, Content-ID assets, calendars, UTF-8 and
SMTPUTF8, 7bit, 8bit, quoted-printable, base64 and binary encodings, long and
folded duplicate headers, arbitrary and nested-message attachments, a 70-byte
MIME boundary token, opaque PGP/MIME, opaque enveloped and signed S/MIME, and a
four-message reverse-alias thread. Crypto parts are intentionally opaque
transport fixtures; this package tests preservation, not trust or signature
validity.

Exact-size EMLs are generated for one byte below the configured limit, the
limit itself, and one byte above it. The first two must be delivered intact and
the last must be rejected definitively.

The deterministic fault matrix executes duplicate acceptance notices,
duplicate and reordered feedback, invalid and replayed signatures, rejection,
delay, soft and hard bounce, complaint, timeouts before and after acceptance,
process loss after durable DATA, credential failure, quota exhaustion, provider
pause, cutover, drain, rollback, and resolved and unresolved unknown attempts.
An ambiguous accepted send is never retried automatically.

Run the offline neutral and Mailgun adapter contracts:

```sh
python -m mail_edge_conformance neutral \
  --adapter reference --output /tmp/reference-evidence.json
python -m mail_edge_conformance neutral \
  --adapter mailgun --output /tmp/mailgun-contract-evidence.json
```

The reference adapter is permanently marked non-activatable. The Mailgun run
uses an in-process deterministic HTTP contract and executes the real multipart
adapter code without making a network request.

## Contained SimpleLogin path

After `ops/owned-provider/bin/owned-provider init`, run:

```sh
ops/owned-provider/bin/owned-provider mail-edge-conformance
```

The command builds the pinned application, temporarily routes its outbound SMTP
to the private fixture edge, and exercises this path:

```text
contact -> SimpleLogin inbound handler -> fixture edge -> deterministic provider
        -> Mailpit mailbox -> reverse alias -> SimpleLogin -> fixture edge
        -> deterministic provider -> contact mailbox
```

It compares the exact bytes submitted by the application at the edge with the
message Mailpit received. The comparison uses the neutral transport allowlist
plus an explicit harness-local `Bcc` exception because Mailpit records its SMTP
envelope recipient in that header. This exception is not used by the adapter or
live suites. The harness runs a rich nested MIME message and four alternating
thread messages. The original test relay is restored and the fixture services
are stopped even when the run fails. Evidence is written beneath
`.owned-provider/evidence/`.

## Opt-in live Mailgun qualification

Live qualification sends real messages and is deliberately not exposed through
the normal contained-test command. It does not create domains, write DNS,
change provider configuration, delete mailbox content, trigger complaints, or
deploy anything. Set every value in the process environment from a secret
store; do not put them in a repository file:

```text
MAIL_EDGE_LIVE_MAILGUN_API_KEY
MAIL_EDGE_LIVE_SENDING_DOMAIN
MAIL_EDGE_LIVE_RECIPIENT
MAIL_EDGE_LIVE_ISOLATED_DOMAINS
MAIL_EDGE_LIVE_IMAP_HOST
MAIL_EDGE_LIVE_IMAP_PORT
MAIL_EDGE_LIVE_IMAP_USER
MAIL_EDGE_LIVE_IMAP_PASSWORD
MAIL_EDGE_LIVE_IMAP_FOLDER
MAIL_EDGE_LIVE_SIZE_LIMIT_BYTES
MAIL_EDGE_LIVE_ALLOWED_TRANSPORT_HEADERS
MAIL_EDGE_LIVE_MAILGUN_API_BASE
MAIL_EDGE_LIVE_CONFIRM=isolated-staging-only
```

The sending domain and recipient domain must both be named in
`MAIL_EDGE_LIVE_ISOLATED_DOMAINS`. Reserved example domains are rejected. The
API base is restricted to Mailgun's official US or EU HTTPS endpoint. The size
limit is an asserted test boundary, not a value copied from provider marketing.
The run refuses to start when credentials, the staging assertion, or the limit
are missing.

```sh
python -m mail_edge_conformance live-mailgun \
  --output /secure/evidence/mailgun-live.json
```

The live run sends the complete corpus and three boundary messages, retrieves
them through a controlled read-only IMAP mailbox, performs the semantic
comparison, and correlates a delivered event through Mailgun's Events API. It
forces tracking off and suppresses provider metadata headers while retaining
an event-only opaque edge ID. Current provider-specific behavior is based on
Mailgun's official [prebuilt MIME API](https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages/post-v3--domain-name--messages),
[event model](https://documentation.mailgun.com/docs/mailgun/user-manual/events/event-types),
and [webhook signature procedure](https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/securing-webhooks).

Resend and Cloudflare can be added later by implementing the same adapter and
event contracts in `providers/`; no neutral corpus assertion or activation rule
needs a provider branch. There are intentionally no placeholder adapters.
Cloudflare's current raw-send and event surfaces are documented in its official
[Email Sending API](https://developers.cloudflare.com/api/resources/email_sending)
and [event subscriptions](https://developers.cloudflare.com/email-service/platform/event-subscriptions/).

## Activation evidence

Evidence documents are content-digested JSON. Their status vocabulary is only
`passed`, `failed`, or `blocked`, and every result states whether it was
executed or fault-injected. There is no field for advertised, available,
selected, beta, or marketing status.

Activation requires matching adapter versions, source revisions, current
corpus digests, and three evidence modes:

1. the full offline adapter contract, corpus, size boundary, and fault matrix;
2. the contained SimpleLogin-to-reverse-alias end-to-end run; and
3. the full live corpus, live size boundary, isolated-domain proof, mailbox
   delivery correlation, and provider event correlation.

```sh
python -m mail_edge_conformance policy --adapter mailgun \
  /secure/evidence/mailgun-contract.json \
  /secure/evidence/mailgun-local-e2e.json \
  /secure/evidence/mailgun-live.json
```

The command exits nonzero and lists every missing or failed observation until
all gates pass.
