"""Exercise real database queue deduplication, failure, stale-take retry, and completion."""

from __future__ import annotations

import argparse
import json
import os
import time

import arrow

from app.db import Session
from app.jobs.export_user_data_job import ExportUserDataJob
from app.models import Job, JobState, User
from server import create_light_app


def user():
    value = User.get_by(email=os.environ["ADMIN_EMAIL"])
    if value is None:
        raise RuntimeError("operator account is missing")
    return value


def create() -> dict:
    job = ExportUserDataJob(user()).store_job_in_db()
    if job is None:
        raise RuntimeError("an export job is already pending")
    duplicate = ExportUserDataJob(user()).store_job_in_db()
    if duplicate is not None:
        raise RuntimeError("duplicate export job was accepted")
    return {"job_id": job.id, "duplicate_suppressed": True}


def wait_for(job_id: int, expected: str, timeout: int) -> dict:
    expected_state = getattr(JobState, expected).value
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        Session.expire_all()
        job = Job.get(job_id)
        if job is None:
            raise RuntimeError(f"job disappeared: {job_id}")
        if job.state == JobState.error.value:
            raise RuntimeError(f"job entered terminal error after {job.attempts} attempts")
        if job.state == expected_state:
            return {
                "job_id": job.id,
                "state": expected,
                "attempts": job.attempts,
                "taken_at": job.taken_at.isoformat() if job.taken_at else None,
            }
        time.sleep(0.5)
    raise RuntimeError(f"job {job_id} did not reach {expected} within {timeout}s")


def age(job_id: int) -> dict:
    job = Job.get(job_id)
    if job.state != JobState.taken.value or job.attempts < 1:
        raise RuntimeError("job must have a failed taken attempt before it can be aged")
    job.taken_at = arrow.now().shift(minutes=-31)
    Session.commit()
    return {"job_id": job.id, "aged_for_retry": True, "attempts": job.attempts}


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("create")
    wait_parser = subparsers.add_parser("wait")
    wait_parser.add_argument("job_id", type=int)
    wait_parser.add_argument("state", choices=("ready", "taken", "done"))
    wait_parser.add_argument("--timeout", type=int, default=60)
    age_parser = subparsers.add_parser("age")
    age_parser.add_argument("job_id", type=int)
    args = parser.parse_args()
    with create_light_app().app_context():
        if args.action == "create":
            result = create()
        elif args.action == "wait":
            result = wait_for(args.job_id, args.state, args.timeout)
        else:
            result = age(args.job_id)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
