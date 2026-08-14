import hashlib
import io
import tempfile

import pytest

from app.mail_edge.configuration import HostDeliveryLimits, MimeParserLimits
from app.mail_edge.errors import MailEdgeBackpressureError, MailEdgeContractError
from app.mail_edge.resources import (
    HostResourceAdmissionService,
    RawMessageResource,
    ResourceSnapshot,
)


def limits(**overrides):
    values = {
        "callback_concurrency": 2,
        "delivery_concurrency": 1,
        "maximum_in_flight_raw_bytes": 100,
        "maximum_in_flight_memory_bytes": 400,
        "maximum_process_rss_bytes": 2_000,
        "minimum_spool_free_bytes": 100,
        "estimated_memory_multiplier": 2,
        "estimated_memory_fixed_bytes": 10,
        "spool_directory": tempfile.gettempdir(),
        "mime": MimeParserLimits(32, 8, 128, 64_000, 64_000, 1_000_000, 5),
    }
    values.update(overrides)
    return HostDeliveryLimits(**values)


def test_raw_resource_is_file_backed_exact_and_always_closed():
    raw = b"From: sender@example.net\r\n\r\nbody"
    opened = []

    def open_file():
        handle = tempfile.TemporaryFile(mode="w+b")
        opened.append(handle)
        return handle

    with RawMessageResource(
        1024, tempfile.gettempdir(), open_file=open_file
    ) as resource:
        assert resource.is_file_backed
        resource.write(raw[:7])
        resource.write(raw[7:])
        resource.seal(
            expected_size=len(raw), expected_sha256=hashlib.sha256(raw).hexdigest()
        )
        copied = io.BytesIO()
        resource.copy_to(copied, chunk_size=3)
        assert copied.getvalue() == raw
    assert opened[0].closed
    resource.close()


def test_raw_resource_rejects_overflow_and_integrity_mismatch():
    with RawMessageResource(3, tempfile.gettempdir()) as resource:
        with pytest.raises(MailEdgeContractError) as raised:
            resource.write(b"four")
        assert raised.value.code == "RAW_MESSAGE_SIZE_INVALID"

    with RawMessageResource(10, tempfile.gettempdir()) as resource:
        resource.write(b"body")
        with pytest.raises(MailEdgeContractError) as raised:
            resource.seal(expected_size=4, expected_sha256="0" * 64)
        assert raised.value.code == "MAIL_EDGE_RAW_DOWNLOAD_INTEGRITY_INVALID"


def test_admission_reserves_concurrency_memory_rss_and_spool_until_release():
    observed = ResourceSnapshot(process_rss_bytes=1_000, spool_free_bytes=1_000)
    admission = HostResourceAdmissionService(
        limits(), 40, snapshot=lambda _directory: observed
    )
    assert admission.ready()

    callback_one = admission.acquire_callback()
    callback_two = admission.acquire_callback()
    with pytest.raises(MailEdgeBackpressureError) as raised:
        admission.acquire_callback()
    assert raised.value.code == "HOST_CALLBACK_CONCURRENCY_EXHAUSTED"

    delivery = admission.acquire_delivery(40)
    with pytest.raises(MailEdgeBackpressureError) as raised:
        admission.acquire_delivery(40)
    assert raised.value.code == "HOST_DELIVERY_RESOURCES_EXHAUSTED"

    delivery.release()
    admission.acquire_delivery(40).release()
    callback_one.release()
    callback_one.release()
    callback_two.release()


@pytest.mark.parametrize(
    ("snapshot", "overrides"),
    (
        (ResourceSnapshot(1_951, 1_000), {}),
        (ResourceSnapshot(100, 119), {}),
        (
            ResourceSnapshot(100, 1_000),
            {"maximum_in_flight_memory_bytes": 40},
        ),
    ),
)
def test_admission_fails_before_download_when_a_resource_ceiling_is_exhausted(
    snapshot, overrides
):
    admission = HostResourceAdmissionService(
        limits(**overrides), 20, snapshot=lambda _directory: snapshot
    )
    with pytest.raises(MailEdgeBackpressureError) as raised:
        admission.acquire_delivery(20)
    assert raised.value.delivery_certainty == "not_sent"
    assert raised.value.retryable


def test_spool_probe_and_open_fail_as_typed_backpressure():
    admission = HostResourceAdmissionService(
        limits(spool_directory="/path/that/does/not/exist"),
        20,
        snapshot=lambda _directory: ResourceSnapshot(100, 1_000),
    )
    assert not admission.ready()
    with pytest.raises(MailEdgeBackpressureError) as raised:
        admission.open_raw_message()
    assert raised.value.code == "HOST_SPOOL_UNAVAILABLE"
