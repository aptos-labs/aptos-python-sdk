"""Unit tests for HttpClient — retry logic, sessions, error handling."""

import aiohttp
import pytest
from aioresponses import aioresponses

from aptos_sdk_v2.api.http_client import _USER_AGENT, HttpClient
from aptos_sdk_v2.config import AptosConfig
from aptos_sdk_v2.errors import ApiError

NODE = "https://fullnode.devnet.aptoslabs.com/v1"


@pytest.fixture
def config():
    return AptosConfig(max_retries=2)


@pytest.fixture
async def client(config):
    c = HttpClient(config)
    yield c
    await c.close()


class TestGet:
    async def test_successful_get(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/foo", payload={"bar": 1})
            result = await client.get(f"{NODE}/foo")
            assert result == {"bar": 1}

    async def test_get_passes_kwargs(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/foo?x=1", payload={"ok": True})
            result = await client.get(f"{NODE}/foo", params={"x": "1"})
            assert result == {"ok": True}


class TestPost:
    async def test_successful_post(self, client):
        with aioresponses() as m:
            m.post(f"{NODE}/bar", payload={"id": 42})
            result = await client.post(f"{NODE}/bar", json={"data": "test"})
            assert result == {"id": 42}


class TestPostBcs:
    async def test_post_bcs_content_type(self, client):
        with aioresponses() as m:
            m.post(f"{NODE}/transactions", payload={"hash": "0xabc"})
            result = await client.post_bcs(f"{NODE}/transactions", b"\x00\x01")
            assert result == {"hash": "0xabc"}

    async def test_post_bcs_for_simulation(self, client):
        with aioresponses() as m:
            m.post(
                f"{NODE}/transactions/simulate",
                payload=[{"success": True}],
            )
            result = await client.post_bcs_for_simulation(
                f"{NODE}/transactions/simulate", b"\x00\x01"
            )
            assert result == [{"success": True}]
            assert isinstance(result, list)


class TestErrorHandling:
    async def test_4xx_raises_immediately(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/bad", status=404, body="not found")
            with pytest.raises(ApiError) as exc_info:
                await client.get(f"{NODE}/bad")
            assert exc_info.value.status_code == 404

    async def test_4xx_no_retry(self, client):
        """4xx (non-429) should NOT be retried — only one request made."""
        with aioresponses() as m:
            m.get(f"{NODE}/bad", status=400, body="bad request")
            with pytest.raises(ApiError) as exc_info:
                await client.get(f"{NODE}/bad")
            assert exc_info.value.status_code == 400


class TestRetryLogic:
    async def test_429_retries_then_raises(self, client):
        with aioresponses() as m:
            # max_retries=2 → 3 total attempts (attempt 0, 1, 2)
            for _ in range(3):
                m.get(f"{NODE}/throttle", status=429, body="rate limited")
            with pytest.raises(ApiError) as exc_info:
                await client.get(f"{NODE}/throttle")
            assert exc_info.value.status_code == 429

    async def test_5xx_retries_then_raises(self, client):
        with aioresponses() as m:
            for _ in range(3):
                m.get(f"{NODE}/error", status=500, body="server error")
            with pytest.raises(ApiError) as exc_info:
                await client.get(f"{NODE}/error")
            assert exc_info.value.status_code == 500

    async def test_5xx_succeeds_on_retry(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/flaky", status=503, body="unavailable")
            m.get(f"{NODE}/flaky", payload={"ok": True})
            result = await client.get(f"{NODE}/flaky")
            assert result == {"ok": True}

    async def test_429_succeeds_on_retry(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/rate", status=429, body="slow down")
            m.get(f"{NODE}/rate", payload={"data": "ok"})
            result = await client.get(f"{NODE}/rate")
            assert result == {"data": "ok"}

    async def test_client_error_retries_then_raises(self, client):
        with aioresponses() as m:
            for _ in range(3):
                m.get(f"{NODE}/conn", exception=aiohttp.ClientConnectionError("fail"))
            with pytest.raises(ApiError) as exc_info:
                await client.get(f"{NODE}/conn")
            assert exc_info.value.status_code == 0

    async def test_client_error_succeeds_on_retry(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/conn", exception=aiohttp.ClientConnectionError("fail"))
            m.get(f"{NODE}/conn", payload={"recovered": True})
            result = await client.get(f"{NODE}/conn")
            assert result == {"recovered": True}


class TestApiKey:
    async def test_bearer_token_in_headers(self):
        config = AptosConfig(api_key="my-secret-key")
        client = HttpClient(config)
        with aioresponses() as m:
            m.get(f"{NODE}/auth", payload={"ok": True})
            result = await client.get(f"{NODE}/auth")
            assert result == {"ok": True}
            # Verify the session was created with the Authorization header
            session = client._ensure_session()
            assert session.headers["Authorization"] == "Bearer my-secret-key"
            assert session.headers["User-Agent"] == _USER_AGENT

    async def test_no_auth_header_without_key(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/noauth", payload={"ok": True})
            await client.get(f"{NODE}/noauth")
            session = client._ensure_session()
            assert "Authorization" not in session.headers


class TestSession:
    def test_lazy_session_not_created_on_init(self, client):
        assert client._session is None
        assert client._connector is None

    async def test_session_created_on_first_request(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/init", payload={"ok": True})
            await client.get(f"{NODE}/init")
            assert client._session is not None
            assert not client._session.closed

    async def test_close_cleans_up(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/init", payload={"ok": True})
            await client.get(f"{NODE}/init")

        session = client._session
        connector = client._connector
        await client.close()
        assert session.closed
        assert connector.closed

    async def test_close_without_session_is_safe(self, client):
        await client.close()  # Should not raise

    async def test_close_connector_without_session(self):
        """Cover the branch where connector exists but session is None/closed."""
        config = AptosConfig()
        client = HttpClient(config)
        # Manually set a live connector without a session
        connector = aiohttp.TCPConnector()
        client._connector = connector
        await client.close()
        assert connector.closed

    async def test_session_recreated_after_close(self, client):
        with aioresponses() as m:
            m.get(f"{NODE}/first", payload={"n": 1})
            await client.get(f"{NODE}/first")

        first_session = client._session
        await client.close()

        with aioresponses() as m:
            m.get(f"{NODE}/second", payload={"n": 2})
            result = await client.get(f"{NODE}/second")
            assert result == {"n": 2}
            assert client._session is not first_session
