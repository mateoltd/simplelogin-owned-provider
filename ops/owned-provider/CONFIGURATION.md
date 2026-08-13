# Configuration and secrets

## Configuration boundary

`config.production.env.example` is a schema, not deployable configuration.
Maintain the effective file outside Git with mode 0600. `production-audit`
rejects test mode, HTTP public URLs, test sinks, reserved domains, missing
public outbound IPs, missing secrets, and unsafe secret permissions.

`OWNED_PROVIDER_ALIAS_DOMAINS` lists provider-wide alias domains.
`OWNED_PROVIDER_CUSTOM_DOMAINS` lists any operator-owned domains to
pre-provision. Both are JSON arrays and may contain arbitrary operator-owned
domains. `OWNED_PROVIDER_E2E_*` values belong only to the contained
verification environment.

Use a TLS reverse proxy in front of the loopback HTTP listener. The implemented
target mail topology uses the separately deployed mail-edge, not a public
application SMTP listener. Configure SimpleLogin outbound relay to the private
mail-edge spool on port 2525 only after the edge generation is qualified and the
neutral UUIDv7 submission contract is integrated. The current production audit
still rejects Mailpit but does not validate or activate mail-edge.

## Independent mail-edge configuration

Mail-edge configuration is not added to `config.production.env.example` or the
SimpleLogin Compose secret set. Keep its runtime, database role, blob volume,
backups, and secrets independently owned. `mail-edge/config.example.env` is a
path-only schema for:

- an edge-only PostgreSQL URL file;
- a mode-0700 durable blob root and an AES-GCM key-ring file;
- a provider-credential file keyed by opaque `credential_ref`;
- a diagnostic hashing salt;
- the neutral HTTPS handoff URL and isolated bearer-token file;
- the hook certificate and private-key files.

All secret files must be regular mode-0600 files. Do not put provider keys,
passwords, webhook signing keys, database URLs, handoff tokens, or blob keys in a
binding JSON, environment value, Compose metadata, command line, image, or this
repository. A Mailgun binding JSON contains only `credential_ref`, `smtp_host`,
and `smtp_port`; unknown fields fail closed.

Inbound and outbound bindings are created and activated separately. The staged
sequence is `prepared`, `shadow`, `active`, `draining`, `disabled`. A shadow-to-
active transition fails unless the edge capability registry has current passing
evidence for every product-policy requirement. Provider GA status is not an
activation input. See [the mail-edge decision](MAIL_EDGE_ARCHITECTURE.md) and the
package [operator guide](../../mail-edge/README.md).

## Secret inventory

`init` creates independent secrets for PostgreSQL, Flask sessions, partner API
tokens, recovery codes, alias transfer, VERP, field encryption, MACs, abuse
derivation, the initial operator password, DKIM, and backup encryption. They are
mounted as files and loaded only at process start; they are not embedded in
Compose environment metadata.

Keep secrets stable across upgrades. The encrypted backup contains the service
configuration and every service secret except `backup_encryption_key`. Store
that key separately in a secrets manager or offline escrow. Losing it makes
backups unrecoverable; storing it beside the backup defeats the isolation.

Rotate one secret at a time with a documented compatibility check. Do not
rotate encryption, MAC, VERP, or signing material until the upstream data and
mail consequences are understood and a restore checkpoint is verified.

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

That lifecycle command changes a SimpleLogin-owned domain record only. It does
not create a Mailgun domain, route, webhook, binding, capability record, or DNS
record. Product-domain verification and mail-edge route activation are distinct
gates and neither substitutes for the other.
