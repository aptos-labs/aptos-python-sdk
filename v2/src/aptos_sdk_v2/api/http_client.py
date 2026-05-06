"""HTTP client wrapper around aiohttp with retry and connection pooling."""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from .._version import __version__
from ..config import AptosConfig
from ..errors import ApiError

_USER_AGENT = f"aptos-python-sdk-v2/{__version__}"


class HttpClient:
    """Async HTTP client with connection pooling, retry logic, and lazy session creation."""

    __slots__ = ("_config", "_session", "_connector")

    def __init__(self, config: AptosConfig) -> None:
        self._config = config
        self._session: aiohttp.ClientSession | None = None
        self._connector: aiohttp.TCPConnector | None = None

    def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._connector = aiohttp.TCPConnector(limit=100, limit_per_host=25)
            headers: dict[str, str] = {"User-Agent": _USER_AGENT}
            if self._config.api_key:
                headers["Authorization"] = f"Bearer {self._config.api_key}"
            self._session = aiohttp.ClientSession(
                connector=self._connector,
                headers=headers,
            )
        return self._session

    async def get(self, url: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request("POST", url, **kwargs)

    async def post_view(self, url: str, **kwargs: Any) -> list[Any]:
        """POST to a view endpoint that returns a JSON array."""
        return await self._request("POST", url, **kwargs)

    async def post_bcs(self, url: str, data: bytes) -> dict[str, Any]:
        """POST BCS-encoded bytes."""
        return await self._request(
            "POST",
            url,
            data=data,
            headers={"Content-Type": "application/x.aptos.signed_transaction+bcs"},
        )

    async def post_bcs_for_simulation(self, url: str, data: bytes) -> list[dict[str, Any]]:
        """POST BCS-encoded bytes for simulation (returns a list)."""
        return await self._request(
            "POST",
            url,
            data=data,
            headers={"Content-Type": "application/x.aptos.signed_transaction+bcs"},
            expect_list=True,
        )

    async def _request(
        self,
        method: str,
        url: str,
        *,
        expect_list: bool = False,
        **kwargs: Any,
    ) -> Any:
        session = self._ensure_session()
        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                async with session.request(method, url, **kwargs) as resp:
                    if resp.status >= 400:
                        body = await resp.text()
                        if resp.status == 429 or resp.status >= 500:
                            last_error = ApiError(body, resp.status)
                            if attempt < self._config.max_retries:
                                await asyncio.sleep(2**attempt * 0.25)
                                continue
                        raise ApiError(body, resp.status)

                    if expect_list:
                        return await resp.json()
                    return await resp.json()
            except aiohttp.ClientError as e:
                last_error = ApiError(str(e), 0)
                if attempt < self._config.max_retries:
                    await asyncio.sleep(2**attempt * 0.25)
                    continue

        raise last_error  # type: ignore[misc]

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        if self._connector and not self._connector.closed:
            await self._connector.close()
