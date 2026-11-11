"""Pytest-wide hooks.

The engine integration tests boot a real Ghidra JVM inside the pytest
process. Ghidra keeps non-daemon Java threads alive, which makes both
``jpype.shutdownJVM()`` and the interpreter's own atexit teardown hang
forever. EngineManager.shutdown() therefore abandons JVM teardown after a
grace period; this hook force-exits the pytest process once everything
(including the terminal summary) has been written — but only when engine
tests actually ran, so plain unit-test runs are untouched.
"""

from __future__ import annotations

import os
import sys

import pytest

_engine_ran = False


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    global _engine_ran
    if item.get_closest_marker("engine"):
        _engine_ran = True
    yield


def pytest_unconfigure(config):
    if _engine_ran:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            pass
        os._exit(int(getattr(config, "exitstatus", 0) or 0))
