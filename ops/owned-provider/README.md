# Owned SimpleLogin provider

This directory is a reusable, production operations overlay for SimpleLogin.
`UPSTREAM_COMMIT` machine-checks the official upstream pin
`dbc45fcce4e8e6b4fa615cc729ca95a67bf75266`. All changes remain below
`ops/owned-provider/` (plus the repository ignore rule), keeping upgrades
replayable.

It operates arbitrary operator-owned alias domains and mailboxes through the
upstream API and mail pipeline. The overlay supplies deployment lifecycle,
observability, capacity validation, upgrades, and disaster recovery.

## Contained end-to-end environment

Requirements: Docker Compose, Git, curl, OpenSSL, Python 3, and `shasum`.

```sh
ops/owned-provider/bin/owned-provider init
ops/owned-provider/bin/owned-provider up
ops/owned-provider/bin/owned-provider e2e
ops/owned-provider/bin/owned-provider drill
```

`init` creates `.owned-provider/config.env` plus independent mode-0600 secrets.
HTTP, metrics, and the Mailpit UI bind to loopback. Application SMTP on 20381
and the authenticated mail-feedback API on 7781 are available only on the
Compose network. Mailpit is the test-only `mail-edge-smtp` endpoint on port
2525. RFC-reserved example domains are used except for the configurable
mailbox-domain MX lookup. Nothing publishes mail or changes DNS.

Local endpoints are API `http://127.0.0.1:17777`, readiness/metrics
`http://127.0.0.1:19090`, and Mailpit
`http://127.0.0.1:18025`.

## Production configuration

Copy `config.production.env.example` to a mode-0600 file outside Git, replace
every example, and point the CLI at it:

```sh
export OWNED_PROVIDER_CONFIG_FILE=/secure/simplelogin/config.env
export OWNED_PROVIDER_RUNTIME_DIR=/secure/simplelogin/runtime
ops/owned-provider/bin/owned-provider init
ops/owned-provider/bin/owned-provider production-audit
ops/owned-provider/bin/owned-provider dns-preflight mask.example.org
ops/owned-provider/bin/owned-provider up
```

Production bootstrap creates domain records in an unverified state. A domain is
marked verified only by the explicit `lifecycle domain-verify` command using a
passing preflight report for that exact domain. The preflight is read-only.

Provider alias capacity has no configured count ceiling. Request-rate, process,
memory, file-descriptor, SMTP message-size, connection, queue batch, and disk
alerts provide bounded-resource protection without an alias-count cap.

## Operator commands

Run the CLI without arguments for the complete command list. Common commands:

```sh
ops/owned-provider/bin/owned-provider status
ops/owned-provider/bin/owned-provider metrics
ops/owned-provider/bin/owned-provider probe
ops/owned-provider/bin/owned-provider reconcile
ops/owned-provider/bin/owned-provider load 10000
ops/owned-provider/bin/owned-provider backup /backups/provider.opb
ops/owned-provider/bin/owned-provider restore /backups/provider.opb
ops/owned-provider/bin/owned-provider upstream-check
```

Runbooks:

- [Configuration and secrets](CONFIGURATION.md)
- [Mail and DNS preflight](MAIL_DNS.md)
- [Mail-edge architecture decision](MAIL_EDGE_ARCHITECTURE.md)
- [Operations, metrics, alerts, and lifecycle](OPERATIONS.md)
- [Disaster recovery](DISASTER_RECOVERY.md)
- [Capacity and scaling](CAPACITY.md)
- [Upstream drift and upgrades](UPSTREAM_SYNC.md)
- [Production readiness boundary](PRODUCTION_AUDIT.md)
