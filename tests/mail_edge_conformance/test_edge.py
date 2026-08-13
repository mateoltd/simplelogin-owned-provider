from mail_edge_conformance.qualification import run_failure_matrix, run_neutral_suite


def test_complete_failure_matrix_passes():
    results = run_failure_matrix()
    assert len(results) == 21
    assert all(item.status == "passed" for item in results)
    assert {item.result_id for item in results} >= {
        "fault:events-duplicated",
        "fault:events-reordered",
        "fault:signature-replay",
        "fault:timeout-before-acceptance",
        "fault:timeout-after-acceptance",
        "fault:crash-after-core-data",
        "fault:credential-failure",
        "fault:quota-exhaustion",
        "fault:provider-pause",
        "fault:cutover",
        "fault:drain",
        "fault:rollback",
        "fault:unknown-reconciliation",
    }


def test_reference_adapter_passes_every_neutral_observation():
    results = run_neutral_suite(8192)
    assert len(results) == 39
    assert all(item.status == "passed" for item in results)
