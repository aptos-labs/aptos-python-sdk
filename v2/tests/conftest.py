"""Shared pytest fixtures and test-only compatibility shims."""

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import aiohttp
import pytest
from aioresponses import core as aioresponses_core

AIOHTTP_REQUIRES_STREAM_WRITER = (
    "stream_writer" in aiohttp.ClientResponse.__init__.__code__.co_varnames
)
AIOHTTP_STREAM_WRITER = SimpleNamespace(output_size=0)


class AioresponsesClientResponse(aiohttp.ClientResponse):
    """Provide stream_writer for aioresponses when running against aiohttp 3.14+."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("stream_writer", AIOHTTP_STREAM_WRITER)
        super().__init__(*args, **kwargs)


@pytest.fixture(scope="session", autouse=True)
def setup_aioresponses_aiohttp_compat() -> Generator[None, None, None]:
    """Patch aioresponses ClientResponse for aiohttp 3.14+ compatibility."""
    if not AIOHTTP_REQUIRES_STREAM_WRITER:
        yield
        return

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(aioresponses_core, "ClientResponse", AioresponsesClientResponse)
    yield
    monkeypatch.undo()
