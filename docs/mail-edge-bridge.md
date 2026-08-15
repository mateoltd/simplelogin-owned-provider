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
    "preDispatchRetries": 1,
    "maximumJsonBytes": 1048576,
    "shutdownSeconds": 30
  },
  "hostAuthentication": {
    "audience": "<host-audience>",
    "maximumAgeSeconds": 300,
    "maximumFutureSkewSeconds": 30,
    "maximumRequestBytes": 1048576,
    "callbackLeaseSeconds": 60,
    "verificationKeys": {
      "<key-id>": "secret://host-verification-key"
    }
  },
  "hostDelivery": {
    "callbackConcurrency": 8,
    "deliveryConcurrency": 2,
    "maximumInFlightRawBytes": 52428800,
    "maximumInFlightMemoryBytes": 268435456,
    "maximumProcessRssBytes": 1073741824,
    "minimumSpoolFreeBytes": 67108864,
    "estimatedMemoryMultiplier": 8,
    "estimatedMemoryFixedBytes": 8388608,
    "spoolDirectory": "/tmp",
    "mime": {
      "maximumParts": 256,
      "maximumDepth": 16,
      "maximumHeaderCount": 1024,
      "maximumHeaderBytes": 1048576,
      "maximumLineBytes": 1048576,
      "maximumSemanticBytes": 104857600,
      "parserSeconds": 10
    }
  },
  "operatorAuthentication": {
    "operatorBearerToken": "secret://operator-bearer",
    "privilegedOperatorBearerToken": "secret://privileged-operator-bearer"
  }
}
```

`operatorAuthentication` is optional unless binding transitions or quarantine decisions are used. Its two credentials must be distinct. `authorize_retry` uses only the privileged credential; the remaining lifecycle and terminal-decision operations use the operator credential.

All timeouts, retries, admission limits, and breaker transitions are bounded. `http.concurrency` limits outbound requests to Mail Edge. The separate `hostDelivery` limits protect inbound callbacks in each application worker. Delivery admission reserves the declared raw size, a conservative MIME/handler memory estimate, file-system headroom, and live process RSS before a raw grant is consumed. Set `maximumProcessRssBytes` per worker below the process or container hard limit, leaving headroom for the configured worker count and non-mail traffic. `estimatedMemoryFixedBytes` must cover at least 1 MiB plus 8 KiB for every permitted MIME part; the loader rejects smaller budgets.

Raw uploads are streamed from a seekable source and checked against the returned immutable reference; a response-loss replay can create only unreferenced immutable storage for the edge orphan reaper. Outbound-intent retries reuse the same bounded idempotency key and identical fingerprint. A response whose delivery outcome cannot be established fails closed; it is never rerouted to another transport while the bridge is enabled.

Recipient destinations use tenant-bound keyed identifiers and deterministic authenticated encryption. Mail Edge receives neither account IDs nor alias IDs. Local projections keep only tenant-scoped intent state, quarantine, feedback, callback, replay, and active/draining/retired binding data; provider delivery certainty remains authoritative in Mail Edge.

## Health

`GET /health/mail-edge/livez` reports local process liveness. `GET /health/mail-edge/readyz` requires a database round trip, Mail Edge readiness, writable spool storage, file-system reserve, and enough current per-worker RSS headroom for one maximum-size delivery; it returns `503` otherwise. These routes are registered only when the bridge is configured.

## Inbound host boundary

The configured application registers the frozen host callback URLs:

- `POST /mail-edge/recipients`
- `POST /mail-edge/reverse-route`
- `POST /mail-edge/delivery`
- `POST /mail-edge/feedback`

Each callback requires the ten `HostSignatureV1` HTTP headers. The bridge verifies the exact body digest, expected operation, subject and audience, checks the HMAC-SHA256 signature in constant time, enforces freshness, and durably consumes the nonce before any routing or delivery effect. Successful responses are bounded `application/json` and echo the signed subject in `X-Mail-Edge-Subject-Id`. Errors use the frozen Mail Edge problem shape and never include addresses, raw content, opaque tokens, provider credentials, or exception causes.

Recipient routing returns only tenant-bound opaque destination capabilities. Application delivery accepts only the persisted push destination, an authorized active or draining exact-domain binding generation, and a single-use `application_delivery` raw grant. The raw message is downloaded with destination-scoped authorization into an unlinked, always-file-backed temporary file while its exact length and SHA-256 are checked. MIME parsing reads that file incrementally and rejects excessive lines, headers, parts, nesting, semantic size, structural defects, or parse time before the callback journal crosses the business-effect fence. The same file-backed canonical raw remains available to the existing handler for debugging without creating a second whole-message byte buffer. A completed callback returns its durable acknowledgement without downloading the grant again.

The callback journal fences concurrent attempts. It records the boundary immediately before the existing mail handoff can create external effects. If a process stops or the local handoff is not conclusively successful after that boundary, a later attempt reports a terminal workflow conflict so Mail Edge can quarantine and reconcile it instead of risking duplicate forwarding.

The bridge owns sessions it creates and closes them once at worker shutdown or replacement. Shutdown first rejects new client operations, then waits up to `http.shutdownSeconds` for responses and raw downloads already in flight. A caller-supplied `requests.Session` remains caller-owned unless ownership is transferred explicitly. Cleanup is registered at process exit, not Flask request teardown; request teardown only releases callback admission and database state.

The tenant client also exposes bounded grant issue, download and revocation calls, binding inspection and lifecycle transitions, and inbound and outbound quarantine inspection and decisions. Control responses are checked against the requested tenant and resource identities before local projections change.
