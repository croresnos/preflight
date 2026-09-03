# GitHub governance runbook

The JSON under ".github/rulesets/" is the reviewed source of truth. GitHub does
not apply repository files as rulesets automatically; an administrator must
apply them in Settings > Rules > Rulesets or with the repository rulesets API.

## Activation order

1. Apply "main-integrity.bootstrap.json" to the default branch with an empty
   bypass list. This blocks deletion and force pushes, requires signed commits,
   linear history, pull requests, resolved conversations, current status
   checks, and squash-only merging. Zero approvals is intentional for the
   current single-maintainer phase.
2. Let the CI workflow complete once and confirm the check displayed by GitHub
   is exactly "merge gate".
3. Replace only the required-status-check rule with
   "main-integrity.json". The stable gate depends on every test, distribution,
   native, and dependency-security job and uses an unconditional final check.
4. Apply "immutable-releases.json" to tags matching "v*". Existing v0.7.0 and
   v0.8.0a2 tags must not be changed or recreated. Create future releases as
   signed annotated tags.
5. In Settings > General > Pull Requests, leave only squash merging enabled.

When an independent reviewer joins, set approvals to one and enable stale
approval dismissal, latest-push approval, and Code Owner review. Until then,
the empty bypass list and required checks are the enforceable control.

After applying a file through the API, read the ruleset back and compare the
target, enforcement, conditions, bypass list, and rules. Do not place a token
in the repository or command history.
