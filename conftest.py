import pytest

from samlwrap.verify import reset_seen_assertions


@pytest.fixture(autouse=True)
def _isolate_assertion_replay_store():
    """Keep the process-wide replay ledger from leaking between test cases."""

    reset_seen_assertions()
    yield
    reset_seen_assertions()
