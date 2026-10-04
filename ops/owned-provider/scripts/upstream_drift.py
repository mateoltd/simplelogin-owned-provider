"""Report upstream replay conflicts and compatibility drift without merging refs."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


ROUTE = re.compile(r"@\w+_bp\.route\(([^\n]+)")
ENV_CALL = re.compile(r'(?:getenv|environ\.get)\(["\']([A-Z][A-Z0-9_]+)')
ENV_INDEX = re.compile(r'environ\[["\']([A-Z][A-Z0-9_]+)')


def git(repository: Path, *args: str, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def file_at(repository: Path, revision: str, path: str) -> str:
    result = git(repository, "show", f"{revision}:{path}", check=False)
    return result.stdout if result.returncode == 0 else ""


def lines(repository: Path, *args: str) -> list[str]:
    return [item for item in git(repository, *args).stdout.splitlines() if item]


def signatures(repository: Path, revision: str) -> dict:
    routes = git(
        repository,
        "grep",
        "-h",
        "-E",
        r"@[a-z_]+_bp\.route",
        revision,
        "--",
        "app/api",
        check=False,
    ).stdout.splitlines()
    route_values = sorted({line.strip() for line in routes})
    config = file_at(repository, revision, "app/config.py")
    env_values = sorted(set(ENV_CALL.findall(config)) | set(ENV_INDEX.findall(config)))
    migrations = lines(
        repository,
        "ls-tree",
        "-r",
        "--name-only",
        revision,
        "--",
        "migrations/versions",
    )
    return {"routes": route_values, "environment": env_values, "migrations": migrations}


def report(repository: Path, candidate: str) -> dict:
    refs_before = git(
        repository, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads"
    ).stdout
    pin = (repository / "ops/owned-provider/UPSTREAM_COMMIT").read_text().strip()
    head = git(repository, "rev-parse", "HEAD").stdout.strip()
    candidate_sha = git(
        repository, "rev-parse", f"{candidate}^{{commit}}"
    ).stdout.strip()
    upstream_paths = lines(repository, "diff", "--name-only", pin, candidate_sha)
    overlay_paths = lines(repository, "diff", "--name-only", pin, head)
    replay = git(
        repository,
        "merge-tree",
        "--write-tree",
        "--messages",
        "--name-only",
        "--merge-base",
        pin,
        candidate_sha,
        head,
        check=False,
    )
    baseline = signatures(repository, pin)
    future = signatures(repository, candidate_sha)
    compatibility = {
        "api_routes_added": sorted(set(future["routes"]) - set(baseline["routes"])),
        "api_routes_removed": sorted(set(baseline["routes"]) - set(future["routes"])),
        "config_added": sorted(
            set(future["environment"]) - set(baseline["environment"])
        ),
        "config_removed": sorted(
            set(baseline["environment"]) - set(future["environment"])
        ),
        "migrations_added": sorted(
            set(future["migrations"]) - set(baseline["migrations"])
        ),
        "migrations_removed": sorted(
            set(baseline["migrations"]) - set(future["migrations"])
        ),
        "dockerfile_changed": "Dockerfile" in upstream_paths,
        "mail_handler_changed": "email_handler.py" in upstream_paths,
    }
    refs_after = git(
        repository, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads"
    ).stdout
    return {
        "format": "simplelogin-owned-provider-upstream-drift",
        "format_version": 1,
        "baseline": pin,
        "head": head,
        "candidate": candidate_sha,
        "working_tree_changed": bool(
            git(repository, "status", "--porcelain=v1").stdout.strip()
        ),
        "upstream_commit_count": int(
            git(repository, "rev-list", "--count", f"{pin}..{candidate_sha}").stdout
        ),
        "overlay_paths": overlay_paths,
        "upstream_changed_paths": upstream_paths,
        "path_overlap": sorted(set(overlay_paths) & set(upstream_paths)),
        "replay_conflicts": replay.returncode != 0,
        "replay_report": replay.stdout.splitlines()[1:200],
        "compatibility": compatibility,
        "auto_merged": False,
        "local_branch_refs_changed": refs_before != refs_after,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--candidate", default="upstream/master")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = report(args.repository.resolve(), args.candidate)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    raise SystemExit(1 if result["replay_conflicts"] else 0)


if __name__ == "__main__":
    main()
