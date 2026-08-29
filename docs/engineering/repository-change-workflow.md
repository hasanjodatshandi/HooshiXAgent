# HooshiXAgent Repository Change Workflow

**Status:** Normative
**Canonical workspace:** `D:\Projects\hooshixagent`
**Canonical remote:** `https://github.com/hasanjodatshandi/HooshiXAgent.git`

This workflow applies to every normal Durable Plan implementation leaf.

## 1. Canonical workspace and remote

All authoritative implementation work MUST occur in:

```text
D:\Projects\hooshixagent
```

The canonical Git remote MUST be:

```text
https://github.com/hasanjodatshandi/HooshiXAgent.git
```

Before editing, verify:

- the local path is the canonical workspace;
- `origin` is the canonical remote;
- current branch/state is understood;
- `origin/main` is fetched;
- unrelated dirty work will not be overwritten.

Do not silently move the workspace, repoint `origin`, reset user work, delete uncommitted files, or develop in another authoritative clone.

## 2. One Durable Plan leaf = one branch = one PR

For normal project implementation:

```text
one Durable Plan leaf
= one fresh branch from current origin/main
= one Pull Request to main
= one verified merge to main
```

Do not combine multiple leaves in one branch or PR.

Do not reuse a stale branch for a new leaf.

Direct normal implementation commits to `main` are prohibited.

## 3. Required leaf lifecycle

The required lifecycle is:

```text
plan.resume(project_id="hooshix-agent")
→ plan.next(plan_id)
→ reconcile canonical workspace with origin/main
→ create a fresh leaf branch
→ plan.start(current_leaf)
→ implement ONLY the current leaf
→ run focused local tests/checks
→ run applicable security gates
→ run the Executable Runtime Gate when applicable
→ review diff/scope against the current leaf
→ commit
→ push branch
→ open PR to main
→ review the complete PR diff against latest main
→ required CI executes
→ fix failures in the SAME PR
→ all required checks Passed
→ merge PR
→ verify merged origin/main SHA/state
→ synchronize local main
→ run applicable post-merge runtime/acceptance verification
→ plan.verify_and_complete(PASSED)
→ plan.next
```

A later leaf MUST NOT begin before the current leaf has completed this lifecycle.

## 4. Main-branch discipline

Normal implementation work MUST NOT be committed directly to `main`.

Before creating a leaf branch:

```text
git checkout main
git fetch origin main
git merge --ff-only origin/main
git status --short --branch
git checkout -b <leaf-branch>
```

If local `main` cannot fast-forward cleanly, stop and understand the state. Do not reset or overwrite user work merely to continue.

## 5. PR scope review

Before merge, review the complete PR diff against the latest `main` and verify:

- only the current Durable Plan leaf is implemented;
- no unrelated cleanup/refactor is included;
- no later-leaf scaffolding is included;
- no scope/architecture/technology change bypassed approval/replan/ADR requirements;
- no security/runtime/CI/acceptance gate was weakened;
- required tests/evidence match the leaf acceptance criteria.

## 6. CI relationship

Required CI must run and pass before merge once the applicable CI gates exist for the repository/leaf.

Use exact evidence vocabulary. In particular:

- a missing workflow is not `Passed`;
- a skipped required check is not `Passed`;
- a failing required check blocks merge/completion;
- do not disable or downgrade a failing gate to obtain green status;
- fix CI failures in the same PR.

If a governance leaf precedes the approved CI-foundation leaf and therefore no CI workflow exists yet, report CI as `Not run`; do not pull later-leaf CI implementation forward merely to change the label.

## 7. Merge is necessary but not sufficient

A leaf is not complete merely because:

```text
code/docs exist
local checks pass
runtime checks pass
PR opened
CI green
PR approved
```

Completion requires:

```text
PR merged to main
+ merged origin/main SHA/state verified
+ local main synchronized
+ applicable post-merge verification Passed
+ all required acceptance evidence present
```

Only then may `plan.verify_and_complete(PASSED)` be called.

## 8. Post-merge verification

After merge:

1. fetch `origin/main`;
2. verify the PR is in state `MERGED`;
3. verify the reported merge commit exists on `origin/main`;
4. synchronize local `main` without discarding user work;
5. verify local `HEAD` equals expected `origin/main` when the workspace is clean and authoritative;
6. re-run the leaf's applicable merged-main acceptance/runtime checks;
7. record merge SHA, PR, check status, post-merge result and any checks not run.

A merge SHA without post-merge verification is insufficient for leaf PASS.

## 9. Failure handling

When a local, security, runtime, PR, CI, merge, or post-merge gate fails:

- keep the current leaf active;
- diagnose the failure without broadening scope;
- fix it on the same leaf branch/PR when the fix is in scope;
- re-run the failed and impacted gates;
- do not start the next leaf;
- use the Change Request flow if the approved leaf cannot safely complete without a material change.
