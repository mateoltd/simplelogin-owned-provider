# Upstream synchronization strategy

The branch is a thin operations overlay on an unmodified official source tree.
`UPSTREAM_COMMIT` is the only accepted base identity. Never merge arbitrary fork
branches into this baseline.

## Read-only check

```sh
ops/owned-provider/bin/owned-provider upstream-check
```

This fetches `upstream/master`, reports divergence, and lists the local overlay.
It does not alter the working branch.

## Upgrade procedure

1. Require a clean worktree and a successful baseline `drill`, SDK conformance,
   and `audit`. Preserve the evidence and a restorable backup.
2. Fetch official upstream and review release notes, security advisories,
   migrations, Dockerfile changes, config additions/removals, API changes, and
   mail-handler changes between `UPSTREAM_COMMIT` and the candidate SHA.
3. Create a temporary upgrade branch from
   `integration/owned-provider-baseline`. Rebase the small local commit series
   with `git rebase --onto CANDIDATE_SHA OLD_UPSTREAM_COMMIT`.
4. Change only `UPSTREAM_COMMIT` and operational compatibility code required by
   the candidate. Do not copy upstream files into the overlay.
5. Build without cache once, start from a copy of production-shaped data, run
   migrations, then run `drill`, SDK conformance, and `audit`.
6. Test rollback from the pre-upgrade backup. Database migrations may make code
   rollback unsafe; treat backup restore as the rollback boundary unless the
   upstream migration is explicitly reversible.
7. Review `git diff --stat CANDIDATE_SHA..HEAD`. It must remain limited to
   `.gitignore` and `ops/owned-provider/`. Merge only after evidence review.
8. Push with a normal fast-forward update. Never rewrite the shared baseline
   branch after adoption.

Keep operational fixes as small conventional commits. If a product-code fix is
unavoidable, submit it upstream first and carry one isolated, documented patch
with a removal condition. The current baseline carries no such patch.
