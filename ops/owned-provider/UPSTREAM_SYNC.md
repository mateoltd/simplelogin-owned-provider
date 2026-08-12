# Upstream synchronization and drift lane

The fork is a thin operations overlay on the immutable commit in
`UPSTREAM_COMMIT`. Never merge an arbitrary fork branch into this line and never
change the pin without a reviewed upstream upgrade.

## Read-only drift report

```sh
ops/owned-provider/bin/owned-provider upstream-check
```

The command fetches only `upstream/master` into the existing tracking ref, then
uses `git merge-tree` with the pinned commit as the explicit base. It writes a
JSON report beneath the runtime evidence directory containing:

- exact baseline, local head, and candidate SHAs;
- candidate commit count and changed paths;
- overlap with the operations overlay;
- replay conflict names/messages;
- added/removed API routes, environment keys, and migrations;
- Dockerfile and mail-handler change flags.

It performs no merge, rebase, checkout, branch update, commit, or push. The
report records whether any local branch ref changed while it ran.

## Upgrade lane

1. Require a clean tree and passing `drill`, SDK conformance, `audit`, current
   backup, and clean-machine restore evidence.
2. Run `upstream-check`; review release notes, security advisories, migrations,
   dependency/container changes, API routes, mail handler, configuration, and
   every reported conflict.
3. Create a temporary branch from the provider branch. Replay the small local
   commit series with:

   ```sh
   git rebase --onto CANDIDATE_SHA OLD_UPSTREAM_COMMIT
   ```

4. Change only `UPSTREAM_COMMIT` and compatibility code required by the new
   release. Keep compatibility changes isolated and documented. Do not copy
   upstream application files into the overlay.
5. Build without cache, restore a copy of production-shaped state, migrate, and
   run `production-audit`, `e2e`, `queue-drill`, `restart-drill`, `load`, SDK
   conformance, backup, and clean-machine restore.
6. Prove rollback from the pre-upgrade encrypted backup. Treat database restore
   as the rollback boundary unless every upstream migration is known reversible.
7. Review `git diff --stat CANDIDATE_SHA..HEAD`; changes should remain under
   `.gitignore` and `ops/owned-provider/`. Push only after evidence approval.

Keep operational changes as small conventional commits. If an application-code
fix is unavoidable, submit it upstream and carry one isolated patch with a
documented removal condition.
