# Production readiness boundary

## Implemented in this fork

- pinned official upstream lineage with an allowlisted operations overlay and
  hardened provider-neutral Mail Edge host boundary;
- file-mounted independent secrets, PKCS#1 DKIM key, config fail-closed audit,
  unprivileged read-only application containers, dropped capabilities, resource
  limits, persistent state, and loopback-by-default publication;
- arbitrary operator-owned alias/custom domains with idempotent lifecycle and
  relationship reconciliation;
- real upstream API, SMTP forwarding, outbound sending, reverse aliases,
  mailbox lifecycle, database queue retries, and alias-SDK contract lane;
- upstream plus overlay migrations, dependency readiness, bounded-cardinality
  Prometheus metrics, alert rules, redacted structured logs, and recurring API,
  SMTP-ingress, and outbound-relay synthetic probes;
- no alias-count cap, repeatable 10,000-or-more capacity measurement, and
  bounded resource failure modes;
- read-only MX/SPF/DKIM/DMARC/PTR preflight;
- deterministic all-table digest, full-state export/import, AES-256-GCM backup,
  clean-volume restore, and point-in-time marker proof across owned components;
- a read-only upstream drift lane reporting replay conflicts, routes,
  configuration, migrations, Dockerfile, and mail-handler changes.
- strict rendered Mail Edge configuration, file-mounted key rotation and
  scoped operator secrets, file-backed raw admission, signed callback and raw
  grant validation, fenced same-delivery-ID recovery, local binding/outbound
  projections, edge-aware readiness/metrics, bounded shutdown, and complete
  backup inventory for every local Mail Edge table/config/secret.

## External production requirements

Software cannot truthfully provision or attest these without operator authority:

1. Authoritative DNS and delegated reverse DNS passing the preflight.
2. A production MTA with relay authentication, durable queue backup, deferred/
   bounce/complaint monitoring, reputation and abuse controls.
3. TLS termination, trusted certificates, forwarded-header policy, firewall,
   load balancer, and DDoS controls.
4. Off-host immutable encrypted backup retention and separately audited key
   escrow, plus native backup of every external stateful component.
5. External Prometheus collection, alert routing, host/disk/certificate/MTA
   metrics, and an attended on-call response.
6. Capacity and HA design for the actual traffic/RPO/RTO, including PostgreSQL,
   Redis, SMTP, workers, web, storage, and regional failure.
7. Security/privacy review, admin MFA and access policy, vulnerability and image
   scanning, dependency cadence, data retention, abuse response, and legal
   obligations.
8. A staging drill on the real topology using controlled recipients before any
   public traffic change.
9. A compatible external Mail Edge release, tenant credentials, host-signing
   keys, operator scopes, versioned object storage, KMS, PostgreSQL/queue
   operations, provider qualifications, and its own backup/restore evidence.

`production-audit` validates local configuration; it does not claim these
external controls exist. Do not deploy publicly until each has named evidence
and ownership.
