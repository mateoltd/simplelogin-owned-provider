"""Run a service and emit one redacted JSON object for each output line."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse

EMAIL = re.compile(
    r"(?i)(?<![\w.+-])([\w.!#$%&'*+/=?^`{|}~-]+)@([a-z0-9.-]+\.[a-z]{2,})"
)
IPV4 = re.compile(r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?:\[[0-9A-Fa-f:.%]+\]|[0-9A-Fa-f]*:[0-9A-Fa-f:.%]*)(?![0-9A-Fa-f:])"
)
AUTH = re.compile(
    r"(?i)([\"']?)(authorization|authentication|api[_-]?key|password|secret|token)\1"
    r"(\s*[:=]\s*)([\"']?)(?:(?:bearer|basic)\s+)?([^\"'\s,;}\]]+)\4"
)
LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Fa-f0-9]{40,}(?![A-Za-z0-9])")


def pseudonym(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.lower().encode()).hexdigest()[:12]
    return f"<{kind}:{digest}>"


def secret_values() -> list[str]:
    markers = (
        "SECRET",
        "PASSWORD",
        "TOKEN",
        "PRIVATE_KEY",
        "MAC_KEY",
        "ENC_KEY",
        "SALT",
        "VERP",
    )
    values = {
        value
        for key, value in os.environ.items()
        if value
        and len(value) >= 8
        and (key == "DB_URI" or any(marker in key.upper() for marker in markers))
    }
    secret_directory = Path("/run/secrets")
    if secret_directory.is_dir():
        for path in secret_directory.iterdir():
            if not path.is_file():
                continue
            value = path.read_text(errors="replace").strip()
            if len(value) >= 8:
                values.add(value)
            values.update(line for line in value.splitlines() if len(line) >= 8)
    database_uri = os.environ.get("DB_URI")
    if database_uri:
        password = urlparse(database_uri).password
        if password:
            values.add(password)
    return sorted(values, key=len, reverse=True)


def _redact_ip_candidates(line: str, pattern: re.Pattern[str]) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        unwrapped = candidate[1:-1] if candidate.startswith("[") else candidate
        address = unwrapped.split("%", 1)[0]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return candidate
        return pseudonym("ip", candidate)

    return pattern.sub(replace, line)


def sensitive_kinds(line: str) -> set[str]:
    """Identify raw PII/auth material that the structured wrapper must remove."""
    found: set[str] = set()
    if EMAIL.search(line):
        found.add("email")
    for pattern in (IPV4, IPV6):
        for match in pattern.finditer(line):
            candidate = match.group(0)
            unwrapped = candidate[1:-1] if candidate.startswith("[") else candidate
            try:
                ipaddress.ip_address(unwrapped.split("%", 1)[0])
            except ValueError:
                continue
            found.add("ip")
            break
    for match in AUTH.finditer(line):
        if match.group(5) not in {"<redacted>", "<secret:redacted>"}:
            found.add("auth")
            break
    if LONG_TOKEN.search(line):
        found.add("token")
    return found


def redact(line: str, secrets: list[str]) -> str:
    for value in secrets:
        line = line.replace(value, "<secret:redacted>")
    line = AUTH.sub(
        lambda m: (
            f"{m.group(1)}{m.group(2)}{m.group(1)}{m.group(3)}"
            f"{m.group(4)}<redacted>{m.group(4)}"
        ),
        line,
    )
    line = EMAIL.sub(lambda m: pseudonym("email", m.group(0)), line)
    line = _redact_ip_candidates(line, IPV4)
    line = _redact_ip_candidates(line, IPV6)
    return LONG_TOKEN.sub("<token:redacted>", line)


def level(line: str, stream: str) -> str:
    upper = line.upper()
    for candidate in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
        if candidate in upper:
            return candidate.lower()
    return "error" if stream == "stderr" else "info"


def emit(service: str, stream: str, raw: str, secrets: list[str]) -> None:
    record = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "service": service,
        "stream": stream,
        "level": level(raw, stream),
        "message": redact(raw.rstrip("\r\n"), secrets)[:16_384],
    }
    print(json.dumps(record, sort_keys=True), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--pid-file", type=Path, default=Path("/tmp/service.pid"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")

    child = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    args.pid_file.write_text(f"{child.pid}\n")
    secrets = secret_values()

    def forward(signum, _frame):
        if child.poll() is None:
            os.killpg(child.pid, signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, forward)

    def pump(name, source):
        while chunk := source.readline(16_385):
            emit(args.service, name, chunk, secrets)

    threads = []
    for stream_name, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
        thread = threading.Thread(
            target=pump,
            args=(stream_name, stream),
            daemon=True,
        )
        thread.start()
        threads.append(thread)
    return_code = child.wait()
    for thread in threads:
        thread.join(timeout=5)
    args.pid_file.unlink(missing_ok=True)
    emit(args.service, "supervisor", f"process exited status={return_code}", secrets)
    return return_code


if __name__ == "__main__":
    sys.exit(main())
