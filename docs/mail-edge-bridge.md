# Mail Edge bridge

The Mail Edge bridge is opt-in. With no `MAIL_EDGE_CONFIG_PATH`, alias forwarding and replies keep using the existing SMTP transport. When the variable points to a valid absolute v1 configuration file, alias forwarding and replies use Mail Edge raw-message storage and durable outbound intents. Configuration errors stop application startup.

Alias creation, deletion, ownership, catch-all creation, mailbox selection, contacts, and public alias APIs remain local. The bridge never creates a provider resource for an alias.

## Configuration

Credentials and HMAC key material must be files below the absolute `secretDirectory`. Configuration values refer to them with `secret://` references; inline secrets are rejected.

```json
{
  "schemaVersion": "v1",
  "tenantId": "<uuid-v7>",
  "baseUrl": "https://<private-mail-edge-host>",
  "secretDirectory": "/run/secrets/mail-edge",
  "bearerToken": "secret://tenant-bearer",
  "opaqueTokenKey": "secret://opaque-token-key",
  "maximumRawBytes": 26214400,
  "http": {
    "connectSeconds": 1,
    "readSeconds": 10,
    "concurrency": 32,
    "breakerFailures": 5,
    "breakerResetSeconds": 30,
    "preDispatchRetries": 1
  },
  "hostAuthentication": {
    "audience": "<host-audience>",
    "maximumAgeSeconds": 300,
    "maximumFutureSkewSeconds": 30,
    "verificationKeys": {
      "<key-id>": "secret://host-verification-key"
    }
  }
}
```

All timeouts, retries, admission limits, and breaker transitions are bounded. Raw uploads are streamed from a seekable source, checked against the returned immutable reference, and retried only as a pre-dispatch operation. Outbound-intent retries reuse the same bounded idempotency key and identical fingerprint. A response whose durable outcome cannot be established fails closed; it is never rerouted to another transport while the bridge is enabled.

Recipient destinations use tenant-bound keyed identifiers and deterministic authenticated encryption. Mail Edge receives neither account IDs nor alias IDs. Local projections keep only tenant-scoped intent state, quarantine, feedback, callback, replay, and active/draining/retired binding data; provider delivery certainty remains authoritative in Mail Edge.

## Health

`GET /health/mail-edge/livez` reports local process liveness. `GET /health/mail-edge/readyz` requires both a database round trip and Mail Edge readiness and returns `503` otherwise. These routes are registered only when the bridge is configured.

## Inbound host boundary

The codebase contains the strict recipient-routing, reverse-routing, header-plan, signature/replay, application-delivery, feedback, callback-idempotency, and binding-generation services. They are transport-independent on purpose. Do not register a callback HTTP or SMTP wire adapter until that adapter, raw-reference access mechanism, and destination binding are part of the standalone service's frozen authenticated contract. This prevents an incompatible private protocol from becoming a shipping path.
