# HooshiXAgent Reporting and Evidence Contract

**Status:** Normative

Every non-trivial Durable Plan leaf must report its outcome using the exact evidence vocabulary and receipt defined here.

## 1. Exact check-status vocabulary

Use only these check-status labels:

```text
Passed
Failed
Not run
Not applicable
Partially verified
Inconclusive
Not verified
```

Meanings:

- **Passed** — the required check actually executed with sufficient evidence and satisfied its acceptance condition.
- **Failed** — the check executed and did not satisfy its acceptance condition.
- **Not run** — the check did not execute. State why. `Not run` is never equivalent to `Passed`.
- **Not applicable** — the check genuinely does not apply to the current leaf/capability. State why.
- **Partially verified** — some required evidence exists, but the complete check/acceptance condition was not verified.
- **Inconclusive** — the check executed or evidence was collected, but the result cannot reliably establish pass/fail.
- **Not verified** — the required condition has no sufficient verification evidence.

Do not invent softer aliases such as `mostly passed`, `looks good`, `probably fine`, or `green enough` for required gates.

## 2. Leaf outcome vocabulary

The overall leaf receipt uses:

```text
Outcome:
completed | partial | blocked | failed
```

`completed` is permitted only after all required completion criteria are satisfied.

A leaf with a required `Failed`, `Not run`, `Partially verified`, `Inconclusive`, or `Not verified` check cannot be reported as `completed` unless that check is explicitly and legitimately `Not applicable` or an approved plan/acceptance change has removed the requirement before completion.

## 3. Mandatory evidence receipt

Every non-trivial leaf reports:

```text
Outcome:
completed | partial | blocked | failed

Project:
Plan ID:
Leaf:
Scope:
Out of scope:
Architecture review mode:
ADRs reviewed/created/changed:
Files/components changed:
Contracts changed:
Database/migration impact:
Timeout/retry/cancellation/concurrency impact:
Security/tenant impact:
Observability impact:
Local tests:
Executable Runtime Gate:
Negative/adversarial tests:
CI:
PR:
Merge SHA:
Post-merge verification:
Failed/not-run checks:
Architecture deviations:
Rollback:
Risks:
Remaining work:
Continuation action:
continue | stop | human
Retryable:
yes | no
Human action required:
None | exact action
```

Fields that do not apply must be explicitly marked `Not applicable` with a short reason where ambiguity would otherwise exist. Do not silently omit a required receipt field.

## 4. Required evidence quality

Evidence must be concrete and reproducible enough to support the claimed status.

Examples of useful evidence:

- exact PR number/link;
- merge SHA verified on `origin/main`;
- exact command/check name and observed result;
- runtime procedure and observed behavior;
- negative/adversarial case and observed rejection/failure behavior;
- file/component list;
- CI check names and conclusions;
- post-merge verification result;
- explicit `Not run` / `Not applicable` reasons;
- applicable ADR IDs and status.

Statements such as `tested`, `works`, `CI fine`, `secure`, or `merged` without supporting evidence are insufficient for a non-trivial leaf.

## 5. Completion criteria

A leaf may report `Outcome: completed` only when all applicable requirements are true:

1. the exact current Durable Plan leaf was the only implemented scope;
2. its definition of done and verification specification are satisfied;
3. applicable local/focused tests are `Passed`;
4. applicable security/negative gates are `Passed`;
5. the Executable Runtime Gate is `Passed` when the capability is runnable, or legitimately `Not applicable` with reason;
6. required CI is `Passed` when the applicable CI workflow/gates exist;
7. the PR is merged to `main`;
8. merge SHA/state is verified on `origin/main`;
9. local authoritative `main` is synchronized when required by the workflow;
10. applicable post-merge verification is `Passed`;
11. required evidence is present in the receipt;
12. architecture deviations are either `None` or explicitly approved and traceable through the required ADR/replan process;
13. skipped/non-applicable checks are explicit rather than hidden.

No `completed` outcome with missing required evidence.

## 6. CI/reporting bootstrap rule

During governance leaves that intentionally precede the approved CI-foundation leaf, absence of CI must be reported as:

```text
CI: Not run — CI workflow not yet implemented; its implementation belongs to the approved CI-foundation leaf.
```

This is not a passing CI result and does not authorize pulling later-leaf CI work into the current governance leaf.

Once applicable CI exists, required CI must be `Passed` before merge/completion.

## 7. Architecture deviations

The receipt field `Architecture deviations:` must be exactly one of:

- `None`; or
- an explicit approved deviation/change reference that identifies the user approval and applicable ADR/replan evidence.

An unapproved architecture deviation blocks completion.

Do not label a scope, technology, protocol, trust-boundary, datastore, deployment, or scaling change as minor merely to avoid the change-control process.

## 8. Skipped checks

Every skipped required or potentially applicable check must appear under `Failed/not-run checks:` with:

- check name;
- status (`Failed`, `Not run`, `Partially verified`, `Inconclusive`, or `Not verified`);
- reason;
- whether it blocks completion;
- next action when applicable.

A skipped check hidden from the receipt is an evidence failure.

## 9. Partial, blocked and failed outcomes

Use `partial` when useful in-scope work/evidence exists but completion criteria are not yet met.

Use `blocked` when completion cannot safely proceed because of an external dependency, required human action, unavailable required environment, or material-change boundary.

Use `failed` when the attempted leaf work or required gate failed and the current execution did not recover it.

These outcomes must still report the mandatory receipt fields as far as known and must not be converted to `completed` by omitting failed or missing evidence.

## 10. Rollback and remaining work

The receipt must identify the rollback approach appropriate to the leaf and any remaining work.

Remaining work must distinguish:

- work still required for the current leaf;
- approved later-roadmap work;
- external HooshiX Control Panel work;
- a potential Change Request/material change.

Do not silently implement remaining later-scope work in order to make the current receipt appear complete.
