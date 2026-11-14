import pytest


@pytest.fixture(autouse=True)
def _no_llm_retry_backoff(monkeypatch):
    """The agent loop retries failed model calls with a 30 s+ backoff; tests
    must not sleep through it."""
    from cvepatch.runner import loop
    monkeypatch.setattr(loop, "LLM_RETRY_BACKOFF_S", 0)
