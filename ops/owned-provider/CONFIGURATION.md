# Configuration and secrets

## Configuration boundary

`config.production.env.example` is a schema, not deployable configuration.
Maintain the effective file outside Git with mode 0600. `production-audit`
rejects test mode, HTTP public URLs, test sinks, automatic backup relays,
reserved domains, missing secrets, and unsafe secret permissions.

`OWNED_PROVIDER_ALIAS_DOMAINS` lists provider-wide alias domains.
`OWNED_PROVIDER_CUSTOM_DOMAINS` lists any operator-owned domains to
pre-provision. Both are JSON arrays and may contain arbitrary operator-owned
domains. `OWNED_PROVIDER_E2E_*` values belong only to the contained
verification environment.

Use a TLS reverse proxy in front of the loopback HTTP listener. The application
SMTP listener is Compose-private and accepts mail only from the operator's
inbound edge on that network. Outbound submission goes only to
`mail-edge-smtp:2525`; the production audit rejects the contained test sink and
any automatic backup-relay setting.

## Secret inventory

`init` creates independent secrets for PostgreSQL, Flask sessions, partner API
tokens, recovery codes, alias transfer, VERP, field encryption, MACs, abuse
derivation, the initial operator password, DKIM, the neutral mail-edge HMAC key
set, and backup encryption. They are mounted as files and loaded only at process
start; they are not embedded in Compose environment metadata.

Keep secrets stable across upgrades. The encrypted backup contains the service
configuration and every service secret except `backup_encryption_key`. Store
that key separately in a secrets manager or offline escrow. Losing it makes
backups unrecoverable; storing it beside the backup defeats the isolation.

Rotate one secret at a time with a documented compatibility check. Do not
rotate encryption, MAC, VERP, or signing material until the upstream data and
mail consequences are understood and a restore checkpoint is verified.

The `mail_edge_hmac_keys` secret is a JSON object whose keys are rotation IDs
and whose values are hex-encoded keys. To rotate it, add a new key ID, move the
edge client to that ID, confirm authenticated traffic, then remove the prior ID.
Every request signs key ID, method, path, timestamp, nonce, and the SHA-256 body
digest. Nonces are persisted until the replay window closes.

## Outbound rollback

There is no automatic provider or relay fallback. For a manual rollback, stop
new edge submissions, resolve or quarantine every `unknown` delivery, and
confirm the former relay contains no uncertain attempts. Only then set
`OWNED_PROVIDER_SMTP_RELAY_HOST` and `OWNED_PROVIDER_SMTP_RELAY_PORT` to the
previously qualified internal SMTP endpoint and restart the application
senders. Restore `mail-edge-smtp:2525` before resuming the neutral edge. Never
route an ambiguous delivery to both paths.

## Domain activation

Bootstrap is idempotent and never fabricates production DNS verification.
After authoritative DNS is ready:

```sh
ops/owned-provider/bin/owned-provider dns-preflight mask.example.org
ops/owned-provider/bin/owned-provider lifecycle domain-verify \
  mask.example.org /evidence/dns-mask.example.org-TIMESTAMP.json
```

Mailbox enable/disable actions are also idempotent. The default mailbox cannot
be disabled by the operator helper.
