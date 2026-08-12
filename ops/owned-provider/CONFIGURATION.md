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

Use a TLS reverse proxy in front of the loopback HTTP listener. Expose SMTP only
through the intended firewall/load-balancer path. Configure a real internal MTA
as `OWNED_PROVIDER_SMTP_RELAY_HOST`; the production audit rejects Mailpit.

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
