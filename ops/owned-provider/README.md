# Owned SimpleLogin provider

This directory is a reusable, production operations overlay for SimpleLogin.
`UPSTREAM_COMMIT` machine-checks the official upstream pin
`dbc45fcce4e8e6b4fa615cc729ca95a67bf75266`. The allowlisted fork delta consists
of this operations overlay, the provider-neutral `app/mail_edge` host, and the
reviewed dependency-security migrations for the legacy Flask, authentication,
crypto, persistence, and mail paths. The host audit rejects changes outside
that exact boundary, keeping upgrades replayable.

It operates arbitrary operator-owned alias domains and mailboxes through the
upstream API and mail pipeline. The overlay supplies deployment lifecycle,
observability, capacity validation, upgrades, and disaster recovery.
Mail Edge is opt-in and remains an external durability boundary; this stack
does not embed a provider, account, region, DNS mutation, or migration policy.

## Contained end-to-end environment

Requirements: Docker Compose, Git, curl, OpenSSL, Python 3, and `shasum`.

```sh
ops/owned-provider/bin/owned-provider init
ops/owned-provider/bin/owned-provider up
ops/owned-provider/bin/owned-provider e2e
ops/owned-provider/bin/owned-provider drill
```

`init` creates `.owned-provider/config.env`, a deterministic strict
`.owned-provider/mail-edge.json`, plus independent mode-0600 secrets.
Each runtime derives a collision-resistant Compose project namespace from its
canonical repository and runtime paths. Containers, networks, configs, and
volumes therefore remain private to that runtime. Test ports bind to loopback
and default to Docker-assigned ports so parallel worktrees cannot collide;
Mailpit captures outbound mail, and RFC-reserved example domains are used
except for the configurable mailbox-domain MX lookup. Nothing publishes mail
or changes DNS. After startup, print the exact endpoints with:

```sh
ops/owned-provider/bin/owned-provider endpoints
```

Production uses explicit nonzero ports. An operator may also set a validated
`OWNED_PROVIDER_PROJECT_NAME`; otherwise path-derived isolation remains the
default.

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
ops/owned-provider/bin/owned-provider socket-gate
ops/owned-provider/bin/owned-provider reconcile
ops/owned-provider/bin/owned-provider load 10000
ops/owned-provider/bin/owned-provider backup /backups/provider.opb
ops/owned-provider/bin/owned-provider restore /backups/provider.opb
ops/owned-provider/bin/owned-provider upstream-check
ops/owned-provider/bin/owned-provider mail-edge-contract-check /path/to/mail-edge
ops/owned-provider/bin/owned-provider distribution-audit
```

Runbooks:

- [Configuration and secrets](CONFIGURATION.md)
- [Mail and DNS preflight](MAIL_DNS.md)
- [Operations, metrics, alerts, and lifecycle](OPERATIONS.md)
- [Disaster recovery](DISASTER_RECOVERY.md)
- [Capacity and scaling](CAPACITY.md)
- [Upstream drift and upgrades](UPSTREAM_SYNC.md)
- [Mail Edge contract verification](MAIL_EDGE_VERIFICATION.md)
- [Dependency advisory reachability](DEPENDENCY_AUDIT.md)
- [Runtime and distribution licenses](DISTRIBUTION.md)
- [Production readiness boundary](PRODUCTION_AUDIT.md)
