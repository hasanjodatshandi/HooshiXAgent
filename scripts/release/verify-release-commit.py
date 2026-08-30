#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys

FINAL_GATE = "AG-8 final security / resilience / release gate"


def gh_json(path, fields):
    cmd = ["gh", "api", "--method", "GET"]
    for key, value in fields.items():
        cmd += ["-f", f"{key}={value}"]
    cmd.append(path)
    try:
        return json.loads(subprocess.check_output(cmd, text=True))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"GitHub API query failed for {path}: {exc}") from exc


def load_fixture(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser(description="Verify that a release commit has successful main CI and final release-gate evidence.")
    parser.add_argument("--sha", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--fixture")
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        print("release SHA must be a lowercase 40-hex Git commit", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        print("repository must be owner/name", file=sys.stderr)
        return 2

    if args.fixture:
        fixture = load_fixture(args.fixture)
        runs = fixture.get("workflow_runs", [])
        jobs_by_run = fixture.get("jobs", {})
    else:
        runs_payload = gh_json(
            f"repos/{args.repo}/actions/workflows/ci.yml/runs",
            {"head_sha": args.sha, "branch": "main", "event": "push", "status": "completed", "per_page": "100"},
        )
        runs = runs_payload.get("workflow_runs", [])
        jobs_by_run = None

    candidates = [
        run for run in runs
        if run.get("head_sha") == args.sha
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("status", "completed") == "completed"
        and run.get("conclusion") == "success"
    ]
    if not candidates:
        print(f"release refused: no successful completed main CI push run for exact commit {args.sha}", file=sys.stderr)
        return 1

    candidates.sort(key=lambda run: str(run.get("created_at", "")), reverse=True)
    for run in candidates:
        run_id = str(run.get("id", ""))
        if not run_id:
            continue
        if jobs_by_run is None:
            jobs = gh_json(f"repos/{args.repo}/actions/runs/{run_id}/jobs", {"per_page": "100"}).get("jobs", [])
        else:
            entry = jobs_by_run.get(run_id, jobs_by_run.get(int(run_id) if run_id.isdigit() else run_id, {}))
            jobs = entry.get("jobs", entry if isinstance(entry, list) else [])
        if any(job.get("name") == FINAL_GATE and job.get("conclusion") == "success" for job in jobs):
            print(f"release policy verified: commit={args.sha} ci_run={run_id} final_gate=Passed")
            return 0

    print(f"release refused: exact commit {args.sha} has no successful {FINAL_GATE!r} job", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())