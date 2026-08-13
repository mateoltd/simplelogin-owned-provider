# Provider-neutral Mailgun adapter suite

This directory is an isolated mail-edge package. It deliberately has no import
or persistence dependency on the application. It owns only delivery
correlation, normalized provider feedback, replay tokens, and bounded
diagnostics. It does not own aliases, users, contacts, mailboxes, or reverse
alias rules.

The suite provides:

- signed, replay-protected raw-MIME ingress using Mailgun's SMTP `sender` and
  `recipient` values rather than MIME headers;
- an explicit, disabled-by-default store-and-fetch ingress policy;
- EU and US `/messages.mime` submission with domain-scoped rotating keys,
  separate envelope fields, disabled open/click tracking, and a 24,000,000-byte
  preflight limit;
- provider-neutral accepted, delivered, delayed, bounce, rejection, and
  complaint events;
- durable deduplication, out-of-order event application, submitted/provider
  Message-ID correlation, and ambiguous-attempt reconciliation that never
  resends;
- read-only domain, tracking, and DNS capability discovery; and
- bounded timeouts, safe retry classification, redacted observations, and
  metadata retention pruning.

No adapter automatically selects another provider or domain. An ambiguous
submission remains quarantined until reconciliation finds provider evidence or
an operator resolves it.

## Boundary contract

The caller supplies and receives only types in `mail_edge.contracts`. Mailgun
JSON and form fields are parsed inside `mail_edge.mailgun`; raw provider payloads
are never returned or persisted. The delivery ledger stores the exact envelope
needed for correlation but never stores RFC 822 bytes. Message bytes belong in
the edge's encrypted durable queue and are removed according to that queue's
policy after definitive disposition.

The raw MIME endpoint currently receives both the explicit `from` and `to`
envelope form values and enables Mailgun native-send behavior. Because provider
behavior, account capabilities, and recipient-visible `Return-Path` cannot be
proven by a fake, the live harness treats exact envelope preservation as a
qualification gate rather than assuming it.

## Testing

Run the hermetic suite from this directory:

```sh
python -m pytest
```

The fake transport exists only in `tests/`; production modules use the injected
HTTP transport protocol or the TLS-verifying standard-library implementation.

The live harness is opt-in and nondestructive. It performs read-only discovery
and a Mailgun test-mode submission, which Mailgun processes but does not deliver:

```sh
MAIL_EDGE_LIVE=1 \
MAILGUN_REGION=EU \
MAILGUN_DOMAIN=example.invalid \
MAILGUN_API_KEY=... \
MAILGUN_ENVELOPE_FROM=probe@example.invalid \
MAILGUN_ENVELOPE_TO=sink@example.invalid \
python -m tests.live_mailgun
```

The harness refuses to run without `MAIL_EDGE_LIVE=1`, never creates or updates
domains, routes, webhooks, DNS, suppressions, or credentials, and always sends
with `o:testmode=yes`.

## Provider contract references

The adapter is grounded in Mailgun's current documentation for the
[`/messages.mime` request](https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages/post-v3--domain-name--messages),
[US/EU API bases](https://documentation.mailgun.com/docs/mailgun/api-reference/api-overview),
[raw-MIME ingress fields and retry responses](https://documentation.mailgun.com/docs/mailgun/user-manual/receive-forward-store/receive-http),
[webhook HMAC verification](https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/securing-webhooks),
[event payloads](https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/webhook-payloads),
[read-only Logs queries](https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/logs),
and the three documented
[storage hosts](https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages/delete-v3--domain-name--envelopes).
