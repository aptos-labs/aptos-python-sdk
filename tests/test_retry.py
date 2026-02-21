# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.retry — RetryConfig, is_retryable_status_code, is_retryable,
and with_retry.
"""

import pytest

from aptos_sdk.errors import (
    AptosTimeoutError,
    BadRequestError,
    InternalServerError,
    NetworkError,
    NotFoundError,
    RateLimitedError,
)
from aptos_sdk.retry import (
    DEFAULT_RETRY_CONFIG,
    RetryConfig,
    is_retryable,
    is_retryable_status_code,
    with_retry,
)

# ---------------------------------------------------------------------------
# RetryConfig
# ---------------------------------------------------------------------------


class TestRetryConfig:
    def test_default_max_retries(self):
        assert DEFAULT_RETRY_CONFIG.max_retries == 3

    def test_default_initial_backoff(self):
        assert DEFAULT_RETRY_CONFIG.initial_backoff_ms == 200

    def test_default_max_backoff(self):
        assert DEFAULT_RETRY_CONFIG.max_backoff_ms == 10_000

    def test_default_backoff_multiplier(self):
        assert DEFAULT_RETRY_CONFIG.backoff_multiplier == 2.0

    def test_default_jitter_enabled(self):
        assert DEFAULT_RETRY_CONFIG.jitter is True

    def test_default_retryable_status_codes(self):
        codes = DEFAULT_RETRY_CONFIG.retryable_status_codes
        assert 429 in codes
        assert 500 in codes
        assert 502 in codes
        assert 503 in codes
        assert 504 in codes

    def test_custom_config(self):
        config = RetryConfig(max_retries=5, initial_backoff_ms=50, jitter=False)
        assert config.max_retries == 5
        assert config.initial_backoff_ms == 50
        assert config.jitter is False

    def test_config_is_frozen(self):
        import dataclasses

        config = RetryConfig()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            config.max_retries = 10  # type: ignore[misc]


# ---------------------------------------------------------------------------
# is_retryable_status_code
# ---------------------------------------------------------------------------


class TestIsRetryableStatusCode:
    def test_429_is_retryable(self):
        assert is_retryable_status_code(429)

    def test_500_is_retryable(self):
        assert is_retryable_status_code(500)

    def test_502_is_retryable(self):
        assert is_retryable_status_code(502)

    def test_503_is_retryable(self):
        assert is_retryable_status_code(503)

    def test_504_is_retryable(self):
        assert is_retryable_status_code(504)

    def test_400_not_retryable(self):
        assert not is_retryable_status_code(400)

    def test_401_not_retryable(self):
        assert not is_retryable_status_code(401)

    def test_404_not_retryable(self):
        assert not is_retryable_status_code(404)

    def test_409_not_retryable(self):
        assert not is_retryable_status_code(409)

    def test_200_not_retryable(self):
        assert not is_retryable_status_code(200)

    def test_custom_config_with_custom_codes(self):
        config = RetryConfig(retryable_status_codes=frozenset({418}))
        assert is_retryable_status_code(418, config)
        assert not is_retryable_status_code(429, config)


# ---------------------------------------------------------------------------
# is_retryable
# ---------------------------------------------------------------------------


class TestIsRetryable:
    def test_network_error_is_retryable(self):
        err = NetworkError("connection refused")
        assert is_retryable(err)

    def test_timeout_error_is_retryable(self):
        err = AptosTimeoutError("timeout")
        assert is_retryable(err)

    def test_rate_limited_error_is_retryable(self):
        err = RateLimitedError("rate limited")
        assert is_retryable(err)

    def test_internal_server_error_is_retryable(self):
        err = InternalServerError("server error")
        assert is_retryable(err)

    def test_bad_request_error_not_retryable(self):
        err = BadRequestError("bad request")
        assert not is_retryable(err)

    def test_not_found_error_not_retryable(self):
        err = NotFoundError("not found")
        assert not is_retryable(err)

    def test_generic_exception_not_retryable(self):
        err = ValueError("generic error")
        assert not is_retryable(err)

    def test_internal_server_error_502(self):
        err = InternalServerError("bad gateway", status_code=502)
        assert is_retryable(err)

    def test_internal_server_error_503(self):
        err = InternalServerError("service unavailable", status_code=503)
        assert is_retryable(err)


# ---------------------------------------------------------------------------
# with_retry
# ---------------------------------------------------------------------------


class TestWithRetry:
    async def test_succeeds_on_first_try(self):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            return "success"

        config = RetryConfig(max_retries=3, jitter=False, initial_backoff_ms=1)
        result = await with_retry(fn, config=config)
        assert result == "success"
        assert call_count == 1

    async def test_retries_on_retryable_error(self):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise NetworkError("temporary failure")
            return "success"

        config = RetryConfig(max_retries=3, jitter=False, initial_backoff_ms=1)
        result = await with_retry(fn, config=config)
        assert result == "success"
        assert call_count == 3

    async def test_exhausts_retries_and_raises(self):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            raise NetworkError("persistent failure")

        config = RetryConfig(max_retries=2, jitter=False, initial_backoff_ms=1)
        with pytest.raises(NetworkError):
            await with_retry(fn, config=config)
        # 1 initial + 2 retries = 3 total calls
        assert call_count == 3

    async def test_non_retryable_error_not_retried(self):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            raise BadRequestError("client error")

        config = RetryConfig(max_retries=3, jitter=False, initial_backoff_ms=1)
        with pytest.raises(BadRequestError):
            await with_retry(fn, config=config)
        assert call_count == 1

    async def test_passes_args_to_fn(self):
        async def fn(a, b, *, keyword=None):
            return (a, b, keyword)

        result = await with_retry(fn, 1, 2, keyword="kw")
        assert result == (1, 2, "kw")

    async def test_returns_fn_return_value(self):
        async def fn():
            return {"key": "value"}

        result = await with_retry(fn)
        assert result == {"key": "value"}
