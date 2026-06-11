"""Shared pytest fixtures and markers.

Defines the ``live_llm`` marker used to gate tests that make real LLM API
calls. These tests are skipped automatically unless a real ``OPENAI_API_KEY``
is present in the environment, so the default offline test run (and CI without
secrets) stays green and free.

Run them explicitly with a real key:

    OPENAI_API_KEY=sk-... pytest -m live_llm
"""

import os

import pytest

# Substrings that indicate a placeholder / non-real key. If the key looks like
# one of these, treat it as "no real key" so live tests skip instead of failing
# with auth errors.
_DUMMY_KEY_MARKERS = ("test", "dummy", "fake", "placeholder", "xxx", "changeme")


def _has_real_openai_key() -> bool:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        return False
    lowered = key.lower()
    if any(marker in lowered for marker in _DUMMY_KEY_MARKERS):
        return False
    # Real OpenAI keys start with "sk-" and are reasonably long.
    return key.startswith("sk-") and len(key) >= 20


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live_llm: test makes real LLM API calls; skipped without a real "
        "OPENAI_API_KEY (run with `pytest -m live_llm`).",
    )


def pytest_collection_modifyitems(config, items):
    if _has_real_openai_key():
        return
    skip_live = pytest.mark.skip(
        reason="needs a real OPENAI_API_KEY (live_llm); set one to run."
    )
    for item in items:
        if "live_llm" in item.keywords:
            item.add_marker(skip_live)
