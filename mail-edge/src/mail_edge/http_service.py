"""TLS-only Mailgun ingress and feedback hook service."""

from __future__ import annotations

import json
import os
import re
import ssl
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .contracts import BindingDirection, BindingState
from .errors import ContractError, InvalidTransition, MailEdgeError, UnknownDomain
from .runtime import Runtime, build_runtime, read_secret_file, required_env

_INBOUND = re.compile(r"^/v1/hooks/mailgun/inbound/([0-9a-f-]+)/raw-mime$")
_FEEDBACK = re.compile(r"^/v1/hooks/mailgun/feedback/([0-9a-f-]+)$")


class HookHandler(BaseHTTPRequestHandler):
    runtime: Runtime
    maximum_message_bytes = 25 * 1024 * 1024
    ingress_retention_hours = 24
    maximum_webhook_age_seconds = 900
    server_version = "mail-edge"
    sys_version = ""

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        inbound = _INBOUND.fullmatch(self.path)
        feedback = _FEEDBACK.fullmatch(self.path)
        if not inbound and not feedback:
            self._json_response(404, {"error": "not_found"})
            return
        maximum_body = (
            self.maximum_message_bytes * 3 + 64 * 1024 if inbound else 2 * 1024 * 1024
        )
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._json_response(411, {"error": "content_length_required"})
            return
        if length < 1 or length > maximum_body:
            self._json_response(413, {"error": "payload_too_large"})
            return
        payload = self.rfile.read(length)
        try:
            if inbound:
                self._handle_inbound(inbound.group(1), payload)
            else:
                assert feedback is not None
                self._handle_feedback(feedback.group(1), payload)
        except (UnknownDomain, InvalidTransition):
            self._json_response(406, {"error": "binding_not_applicable"})
        except ContractError as exc:
            status = (
                401 if "signature" in str(exc) or "replay window" in str(exc) else 406
            )
            self._json_response(status, {"error": "invalid_provider_request"})
        except MailEdgeError:
            self._json_response(503, {"error": "durable_commit_unavailable"})
        except Exception:
            self._json_response(503, {"error": "service_unavailable"})

    def _handle_inbound(self, binding_id: str, payload: bytes) -> None:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != (
            "application/x-www-form-urlencoded"
        ):
            raise ContractError("raw MIME hook must use form encoding")
        binding = self.runtime.bindings.get(binding_id)
        if (
            binding.direction is not BindingDirection.INBOUND
            or binding.provider != "mailgun"
        ):
            raise ContractError("binding is not a Mailgun inbound generation")
        adapter = self.runtime.mailgun_adapter(binding)
        notice, message, replay_token = adapter.normalize_inbound(
            payload,
            domain=binding.domain,
            binding_generation=binding.generation,
            maximum_age_seconds=self.maximum_webhook_age_seconds,
        )
        if len(message.raw_mime) > self.maximum_message_bytes:
            self._json_response(413, {"error": "message_too_large"})
            return
        retention = datetime.now(UTC) + timedelta(hours=self.ingress_retention_hours)
        message_id = self.runtime.repository.record_inbound_raw(
            binding.id,
            provider="mailgun",
            provider_event_id=notice.provider_event_id,
            message=message,
            retention_until=retention,
        )
        self.runtime.repository.record_inbound_notice(
            binding.id, notice, retention_until=retention
        )
        self.runtime.repository.consume_replay_token(
            provider="mailgun",
            purpose="inbound",
            token=replay_token,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self.maximum_webhook_age_seconds),
        )
        self._json_response(200, {"status": "committed", "message_id": message_id})

    def _handle_feedback(self, binding_id: str, payload: bytes) -> None:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != (
            "application/json"
        ):
            raise ContractError("feedback hook must use JSON")
        binding = self.runtime.bindings.get(binding_id)
        if (
            binding.direction is not BindingDirection.OUTBOUND
            or binding.provider != "mailgun"
            or binding.state in {BindingState.PREPARED, BindingState.SHADOW}
        ):
            raise ContractError("binding is not a feedback-capable generation")
        adapter = self.runtime.mailgun_adapter(binding)
        event, replay_token = adapter.normalize_feedback(
            payload,
            expected_domain=binding.domain,
            maximum_age_seconds=self.maximum_webhook_age_seconds,
        )
        created = self.runtime.repository.record_feedback(event)
        self.runtime.repository.consume_replay_token(
            provider="mailgun",
            purpose="feedback",
            token=replay_token,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self.maximum_webhook_age_seconds),
        )
        self._json_response(200, {"status": "committed", "created": created})

    def _json_response(self, status: int, document: dict[str, Any]) -> None:
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # The hook path contains only an opaque binding ID. Provider bodies, addresses,
        # client IPs, query strings, and authorization material are never logged here.
        return


def serve(
    runtime: Runtime, host: str, port: int, certificate: str, private_key: str
) -> None:
    handler = type("ConfiguredHookHandler", (HookHandler,), {"runtime": runtime})
    server = ThreadingHTTPServer((host, port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main() -> None:
    runtime = build_runtime()
    private_key = required_env("MAIL_EDGE_HOOK_TLS_KEY_FILE")
    read_secret_file(private_key, maximum_bytes=1024 * 1024)
    serve(
        runtime,
        os.environ.get("MAIL_EDGE_HOOK_HOST", "127.0.0.1"),
        int(os.environ.get("MAIL_EDGE_HOOK_PORT", "8443")),
        required_env("MAIL_EDGE_HOOK_TLS_CERT_FILE"),
        private_key,
    )


if __name__ == "__main__":
    main()
