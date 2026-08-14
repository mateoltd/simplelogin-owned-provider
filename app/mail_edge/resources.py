from __future__ import annotations

import hashlib
import hmac
import os
import resource
import shutil
import sys
import tempfile
import threading
from dataclasses import dataclass
from typing import BinaryIO, Callable, Optional

from .configuration import HostDeliveryLimits
from .errors import MailEdgeBackpressureError, MailEdgeContractError


@dataclass(frozen=True)
class ResourceSnapshot:
    process_rss_bytes: int
    spool_free_bytes: int


def _current_process_rss_bytes() -> int:
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/statm", "r", encoding="ascii") as handle:
                resident_pages = int(handle.read(128).split()[1])
            return resident_pages * os.sysconf("SC_PAGE_SIZE")
        except (IndexError, OSError, ValueError):
            pass
    maximum_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(maximum_rss if sys.platform == "darwin" else maximum_rss * 1024)


def process_resource_snapshot(spool_directory: str) -> ResourceSnapshot:
    return ResourceSnapshot(
        process_rss_bytes=_current_process_rss_bytes(),
        spool_free_bytes=shutil.disk_usage(spool_directory).free,
    )


class ResourceLease:
    def __init__(self, release: Callable[[], None]):
        self._release = release
        self._released = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._release()

    def __enter__(self) -> ResourceLease:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()


class HostResourceAdmissionService:
    """Process-local admission for host callbacks and MIME delivery resources."""

    def __init__(
        self,
        limits: HostDeliveryLimits,
        maximum_raw_bytes: int,
        *,
        snapshot: Callable[[str], ResourceSnapshot] = process_resource_snapshot,
    ):
        if (
            isinstance(maximum_raw_bytes, bool)
            or not isinstance(maximum_raw_bytes, int)
            or maximum_raw_bytes < 1
        ):
            raise ValueError("Host raw resource limit is invalid.")
        self._limits = limits
        self._maximum_raw_bytes = maximum_raw_bytes
        self._snapshot = snapshot
        self._active_callbacks = 0
        self._active_deliveries = 0
        self._reserved_raw_bytes = 0
        self._reserved_memory_bytes = 0
        self._lock = threading.Lock()

    def ready(self) -> bool:
        maximum_memory = (
            self._maximum_raw_bytes * self._limits.estimated_memory_multiplier
            + self._limits.estimated_memory_fixed_bytes
        )
        try:
            observed = self._snapshot(self._limits.spool_directory)
            with tempfile.TemporaryFile(
                mode="w+b", dir=self._limits.spool_directory
            ) as probe:
                probe.write(b"")
                probe.flush()
        except OSError:
            return False
        with self._lock:
            return (
                observed.process_rss_bytes
                + self._reserved_memory_bytes
                + maximum_memory
                <= self._limits.maximum_process_rss_bytes
                and observed.spool_free_bytes
                >= self._reserved_raw_bytes
                + self._maximum_raw_bytes
                + self._limits.minimum_spool_free_bytes
            )

    def open_raw_message(self) -> RawMessageResource:
        try:
            return RawMessageResource(
                self._maximum_raw_bytes, self._limits.spool_directory
            )
        except OSError:
            raise MailEdgeBackpressureError("HOST_SPOOL_UNAVAILABLE") from None

    def acquire_callback(self) -> ResourceLease:
        with self._lock:
            if self._active_callbacks >= self._limits.callback_concurrency:
                raise MailEdgeBackpressureError("HOST_CALLBACK_CONCURRENCY_EXHAUSTED")
            self._active_callbacks += 1
        return ResourceLease(self._release_callback)

    def acquire_delivery(self, raw_size: int) -> ResourceLease:
        if isinstance(raw_size, bool) or not isinstance(raw_size, int) or raw_size < 0:
            raise MailEdgeContractError("APPLICATION_DELIVERY_RAW_SIZE_INVALID")
        estimated_memory = (
            raw_size * self._limits.estimated_memory_multiplier
            + self._limits.estimated_memory_fixed_bytes
        )
        try:
            observed = self._snapshot(self._limits.spool_directory)
        except OSError:
            raise MailEdgeBackpressureError("HOST_RESOURCE_PROBE_UNAVAILABLE") from None
        with self._lock:
            if (
                self._active_deliveries >= self._limits.delivery_concurrency
                or self._reserved_raw_bytes + raw_size
                > self._limits.maximum_in_flight_raw_bytes
                or self._reserved_memory_bytes + estimated_memory
                > self._limits.maximum_in_flight_memory_bytes
                or observed.process_rss_bytes
                + self._reserved_memory_bytes
                + estimated_memory
                > self._limits.maximum_process_rss_bytes
                or observed.spool_free_bytes
                < self._reserved_raw_bytes
                + raw_size
                + self._limits.minimum_spool_free_bytes
            ):
                raise MailEdgeBackpressureError("HOST_DELIVERY_RESOURCES_EXHAUSTED")
            self._active_deliveries += 1
            self._reserved_raw_bytes += raw_size
            self._reserved_memory_bytes += estimated_memory

        return ResourceLease(lambda: self._release_delivery(raw_size, estimated_memory))

    def _release_callback(self) -> None:
        with self._lock:
            if self._active_callbacks <= 0:
                raise RuntimeError("Host callback admission was released twice.")
            self._active_callbacks -= 1

    def _release_delivery(self, raw_size: int, estimated_memory: int) -> None:
        with self._lock:
            if (
                self._active_deliveries <= 0
                or self._reserved_raw_bytes < raw_size
                or self._reserved_memory_bytes < estimated_memory
            ):
                raise RuntimeError(
                    "Host delivery admission accounting is inconsistent."
                )
            self._active_deliveries -= 1
            self._reserved_raw_bytes -= raw_size
            self._reserved_memory_bytes -= estimated_memory


class RawMessageResource:
    """Unlinked, file-backed canonical raw with exact streamed integrity accounting."""

    def __init__(
        self,
        maximum_bytes: int,
        spool_directory: str,
        *,
        open_file: Optional[Callable[[], BinaryIO]] = None,
    ):
        self._maximum_bytes = maximum_bytes
        self._handle = (
            open_file()
            if open_file is not None
            else tempfile.TemporaryFile(mode="w+b", dir=spool_directory)
        )
        self._digest = hashlib.sha256()
        self._observed_bytes = 0
        self._sealed = False
        self._closed = False
        self._io_lock = threading.Lock()

    @property
    def observed_bytes(self) -> int:
        return self._observed_bytes

    @property
    def is_file_backed(self) -> bool:
        try:
            return self._handle.fileno() >= 0
        except (AttributeError, OSError, ValueError):
            return False

    def write(self, chunk: bytes) -> int:
        if self._closed or self._sealed or not isinstance(chunk, bytes):
            raise MailEdgeContractError("RAW_DOWNLOAD_TARGET_INVALID")
        next_size = self._observed_bytes + len(chunk)
        if next_size > self._maximum_bytes:
            raise MailEdgeContractError("RAW_MESSAGE_SIZE_INVALID", http_status=413)
        written = self._handle.write(chunk)
        if written != len(chunk):
            raise MailEdgeContractError("RAW_DOWNLOAD_TARGET_INVALID")
        self._digest.update(chunk)
        self._observed_bytes = next_size
        return written

    def seal(self, *, expected_size: int, expected_sha256: str) -> None:
        if self._closed or self._sealed:
            raise MailEdgeContractError("RAW_DOWNLOAD_TARGET_INVALID")
        self._handle.flush()
        if self._observed_bytes != expected_size or not hmac.compare_digest(
            self._digest.hexdigest(), expected_sha256
        ):
            raise MailEdgeContractError(
                "MAIL_EDGE_RAW_DOWNLOAD_INTEGRITY_INVALID", http_status=502
            )
        self._sealed = True
        self._handle.seek(0)

    def rewind(self) -> BinaryIO:
        if self._closed or not self._sealed:
            raise MailEdgeContractError("RAW_DOWNLOAD_TARGET_INVALID")
        self._handle.seek(0)
        return self._handle

    def copy_to(self, target: BinaryIO, chunk_size: int = 64 * 1024) -> None:
        if not hasattr(target, "write"):
            raise MailEdgeContractError("RAW_DOWNLOAD_TARGET_INVALID")
        with self._io_lock:
            source = self.rewind()
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    break
                written = target.write(chunk)
                if written is not None and written != len(chunk):
                    raise MailEdgeContractError("RAW_DOWNLOAD_TARGET_INVALID")
            source.seek(0)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._handle.close()

    def __enter__(self) -> RawMessageResource:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
