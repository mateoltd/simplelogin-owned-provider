# Mail Edge contract verification

The reviewed external Mail Edge contract is pinned by
`MAIL_EDGE_CONTRACT_COMMIT` to
`762948e1f9ccb57a025151ab824e4a040a30d272`. The remote
`fix/host-outcome-contracts` head, the fetched origin ref, and the clean
detached verification checkout were confirmed at that exact commit.

The owned-provider contract gate passes at this SHA:

```sh
ops/owned-provider/bin/owned-provider mail-edge-contract-check /path/to/mail-edge
```

It builds the reference service and passes its real PostgreSQL, queue, object
store, provider, and HTTP E2E test. The broader external repository verification
still has the following upstream-only test defects. They are not contract or
SimpleLogin host failures, and this repository must not copy Mail Edge code to
hide them.

## Expired absolute test fixtures

Reproducer at the exact reviewed SHA:

```sh
corepack pnpm --filter @mail-edge/postgres test
```

Result: 35 tests pass and these two tests fail in
`packages/postgres/test/integration/runtime.repository.test.ts`:

- `converges inbound dedup races, binds replay, fences routing, and recovers leases`
- `deduplicates feedback, rejects contradictory identities, and replays projection deterministically`

The replay expiries hard-coded at lines 299 and 1096 are
`2026-08-15T01:00:00.000Z` and `2026-08-15T03:00:01.000Z`. PostgreSQL assigns
`created_at` from `clock_timestamp()`, so those values are now expired. The
correct `CHECK (expires_at > created_at)` in
`packages/postgres/migrations/0001_runtime_expand.sql` rejects the rows with
PostgreSQL error `23514`.

The upstream fix is to derive the two test-only expiries from the database
clock plus a fixed TTL. Do not freeze PostgreSQL or JavaScript time, force a
historical `created_at`, or weaken the production constraint. A new contract
SHA is eligible for review only after both tests pass with real current time.

## Late purge-race rejection handler

The test `serializes a real two-session reference-versus-purge race` in
`packages/postgres/test/integration/repositories.test.ts` creates its blocked
`referrer.query()` promise at line 1027 but does not attach the expected
rejection matcher until line 1054, after the purger commits. Under the full
suite's scheduling load, Node reports `PromiseRejectionHandledWarning` and
Vitest records the expected `23514` as an unhandled rejection. Isolated runs can
pass, which confirms that this is a test-harness race rather than a storage
semantic failure.

The upstream fix is to attach the `rejects` assertion when the query promise is
created, then await that already-handled assertion after the purger commits.
That keeps the two-session lock order and verifies that no outbound reference
survives without exposing an unhandled-rejection window.

Do not update `MAIL_EDGE_CONTRACT_COMMIT` until a reviewed upstream commit
contains those test-only fixes and passes both the focused PostgreSQL tests and
the full Mail Edge verification suite.
