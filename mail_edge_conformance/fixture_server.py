"""Process entry points for the private local qualification topology."""

from __future__ import annotations

import argparse
import os
import signal
import threading

from aiosmtpd.controller import Controller

from .fixtures import (
    EdgeSmtpHandler,
    FixtureHttpAdapter,
    FixtureProvider,
    create_provider_server,
    smtp_delivery,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="role", required=True)
    provider = subparsers.add_parser("provider")
    provider.add_argument("--host", default="0.0.0.0")
    provider.add_argument("--port", type=int, default=8080)
    provider.add_argument("--mailbox-host", required=True)
    provider.add_argument("--mailbox-port", type=int, default=1025)
    edge = subparsers.add_parser("edge")
    edge.add_argument("--host", default="0.0.0.0")
    edge.add_argument("--port", type=int, default=1025)
    edge.add_argument("--provider-url", required=True)
    args = parser.parse_args()
    if args.role == "provider":
        state = FixtureProvider(
            deliver=smtp_delivery(args.mailbox_host, args.mailbox_port)
        )
        server = create_provider_server(args.host, args.port, state)
        server.serve_forever()
        return

    controller = Controller(
        EdgeSmtpHandler(FixtureHttpAdapter(args.provider_url)),
        hostname=args.host,
        port=args.port,
        enable_SMTPUTF8=True,
        data_size_limit=int(os.environ.get("MAIL_EDGE_FIXTURE_SIZE_LIMIT", "26214400")),
    )
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    controller.start()
    try:
        stop.wait()
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
