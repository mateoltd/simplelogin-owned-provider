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

The CLI derives `OWNED_PROVIDER_PROJECT_NAME` from the canonical repository and
runtime paths unless an explicit validated name is configured. Compose-scoped
containers, networks, configs, and volumes never use a global fixed name. Test
port value `0` requests an independent Docker-assigned loopback port; use the
`endpoints` command to discover it. Production audit requires every published
port to be explicit and nonzero.

`OWNED_PROVIDER_MAIL_EDGE_ENABLED=1` enables the provider-neutral Mail Edge
host boundary. The CLI deterministically renders every
`OWNED_PROVIDER_MAIL_EDGE_*` limit into the strict v1
`.owned-provider/mail-edge.json`, mounts it read-only at
`/run/mail-edge/config.json`, and sets `MAIL_EDGE_CONFIG_PATH` only when the
integration is enabled. Unknown application config keys and inline secrets are
rejected at process startup. The Mail Edge base URL is an external durability
service, not a provider choice; provider accounts, regions, domains, and DNS
policy do not belong in this overlay.

The default budgets admit at most two simultaneous 25 MiB delivery downloads
per worker, reserve 256 MiB of in-flight memory, require 64 MiB of spool
headroom, and cap a worker at 512 MiB RSS. `production-audit` cross-checks one
maximum-message estimate, SMTP admission, delivery/callback concurrency,
Gunicorn worker count, application container memory, and the 45-second shutdown
grace. Change these values together, based on measured traffic.

Use a TLS reverse proxy in front of the loopback HTTP listener. Expose SMTP only
through the intended firewall/load-balancer path. Configure a real internal MTA
as `OWNED_PROVIDER_SMTP_RELAY_HOST`; the production audit rejects Mailpit.

## Secret inventory

`init` creates independent secrets for PostgreSQL, Flask sessions, partner API
tokens, recovery codes, alias transfer, VERP, field encryption, MACs, abuse
derivation, the initial operator password, DKIM, and backup encryption. They are
mounted as files and loaded only at process start; they are not embedded in
Compose environment metadata. The OIDC token-signing RSA key is generated and
mounted independently as well, so the tracked development key never enters the
production image.

The inventory also contains independent Mail Edge tenant bearer, opaque-token,
current/previous callback verification, operator, and privileged-operator
secrets. The current and previous callback key IDs are configuration values;
the corresponding bytes remain mounted secrets so rotations can overlap. The
operator tokens must be distinct. Replace the generated contained-test values
with credentials issued for the exact external Mail Edge tenant before enabling
production.

Keep secrets stable across upgrades. The encrypted backup contains the service
configuration and every service secret except `backup_encryption_key`. Store
that key separately in a secrets manager or offline escrow. Losing it makes
backups unrecoverable; storing it beside the backup defeats the isolation.

Rotate one secret at a time with a documented compatibility check. Do not
rotate encryption, MAC, VERP, or signing material until the upstream data and
mail consequences are understood and a restore checkpoint is verified.

The raw callback spool is a dedicated writable volume. Files are unlinked,
process-scoped, integrity-checked temporary resources and are intentionally not
backed up. A fresh or restored deployment recreates the empty spool with the
service UID; durable callback fences and projections live in PostgreSQL.

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
