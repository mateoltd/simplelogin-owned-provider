"""Record a completed encrypted backup for freshness alerting."""

from __future__ import annotations

import argparse
import json
from sqlalchemy import text

from app.db import Session
from server import create_light_app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", type=int, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    with create_light_app().app_context():
        Session.execute(
            text("""
            INSERT INTO owned_provider.backup_result(success, size_bytes, sha256)
            VALUES (true, :size, :sha256)
            """),
            {"size": args.size, "sha256": args.sha256},
        )
        Session.commit()
    print(
        json.dumps({"backup_recorded": True, "size_bytes": args.size}, sort_keys=True)
    )


if __name__ == "__main__":
    main()
