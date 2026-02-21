# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Retry strategy for the Aptos Python SDK (Spec 06, P1).

Provides exponential backoff with optional jitter for transient failures such as
network errors, timeouts, and server-side rate limits or errors.

Usage
-----
Basic usage with the default configuration::

    result = await with_retry(client.get_ledger_info)

With arguments and a custom config::

    config = RetryConfig(max_retries=5, initial_backoff_ms=100)
    result = await with_retry(client.get_account, address, config=config)

Standalone retryability check::

    try:
        ...
    except Exception as e:
        if is_retryable(e):
            # safe to retry
            ...

"""

import asyncio
import random
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TypeVar

from .errors import ApiError, AptosTimeoutError, NetworkError

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetryConfig:
    """
    Immutable configuration for the retry strategy.

    Parameters
    ----------
    max_retries:
        Maximum number of retry attempts after the initial call.  A value of
        ``3`` means up to 4 total calls (1 initial + 3 retries).
    initial_backoff_ms:
        Starting backoff duration in milliseconds before the first retry.
        Subsequent retries multiply this by ``backoff_multiplier``.
    max_backoff_ms:
        Hard ceiling on the backoff delay in milliseconds.  The computed
        exponential value is clamped to this limit before jitter is applied.
    backoff_multiplier:
        Factor by which the backoff duration grows on each retry.
        A value of ``2.0`` gives 200 ms, 400 ms, 800 ms, etc. with the
        default ``initial_backoff_ms``.
    jitter:
        When ``True``, the clamped backoff duration is randomised uniformly
        in ``[0, backoff_ms]`` to prevent thundering-herd effects when many
        clients retry simultaneously.
    retryable_status_codes:
        The set of HTTP status codes that are considered transiently
        retryable.  Defaults to ``{429, 500, 502, 503, 504}``.
    """

    max_retries: int = 3
    initial_backoff_ms: int = 200
    max_backoff_ms: int = 10_000
    backoff_multiplier: float = 2.0
    jitter: bool = True
    retryable_status_codes: frozenset[int] = field(
        default_factory=lambda: frozenset({429, 500, 502, 503, 504})
    )


#: Default retry configuration used by :func:`with_retry` and
#: :func:`is_retryable` when no explicit config is provided.
DEFAULT_RETRY_CONFIG = RetryConfig()


# ---------------------------------------------------------------------------
# Retryability helpers
# ---------------------------------------------------------------------------


def is_retryable_status_code(
    status_code: int,
    config: RetryConfig = DEFAULT_RETRY_CONFIG,
) -> bool:
    """
    Return ``True`` if *status_code* is in the config's retryable set.

    Parameters
    ----------
    status_code:
        An HTTP status code integer (e.g. ``429``, ``503``).
    config:
        The :class:`RetryConfig` whose ``retryable_status_codes`` set is
        consulted.  Defaults to :data:`DEFAULT_RETRY_CONFIG`.

    Returns
    -------
    bool
        ``True`` when *status_code* is retryable, ``False`` otherwise.

    Examples
    --------
    >>> is_retryable_status_code(429)
    True
    >>> is_retryable_status_code(400)
    False
    >>> is_retryable_status_code(503)
    True
    """
    return status_code in config.retryable_status_codes


def is_retryable(
    error: Exception,
    config: RetryConfig = DEFAULT_RETRY_CONFIG,
) -> bool:
    """
    Determine whether *error* represents a transiently retryable failure.

    Retryable conditions per spec:

    - :class:`~aptos_sdk.errors.NetworkError` — connection failures before
      receiving any HTTP response (includes
      :class:`~aptos_sdk.errors.ConnectionFailedError`).
    - :class:`~aptos_sdk.errors.AptosTimeoutError` — operation exceeded its
      deadline.
    - :class:`~aptos_sdk.errors.ApiError` with a status code in
      ``config.retryable_status_codes`` (default: 429, 500, 502, 503, 504).
      This covers :class:`~aptos_sdk.errors.RateLimitedError` (429) and
      :class:`~aptos_sdk.errors.InternalServerError` (5xx) as concrete
      subtypes.

    Non-retryable conditions:

    - Parse errors, invalid input, cryptographic failures.
    - HTTP 400 Bad Request — client error, must fix the request.
    - HTTP 404 Not Found — resource does not exist.
    - HTTP 409 Conflict — deterministic server rejection.
    - VM errors — transaction would fail again unchanged.

    Parameters
    ----------
    error:
        The exception to evaluate.
    config:
        The :class:`RetryConfig` providing ``retryable_status_codes``.
        Defaults to :data:`DEFAULT_RETRY_CONFIG`.

    Returns
    -------
    bool
        ``True`` when the error is safe to retry, ``False`` otherwise.

    Examples
    --------
    >>> from aptos_sdk.errors import NetworkError, RateLimitedError, BadRequestError
    >>> is_retryable(NetworkError("connection refused"))
    True
    >>> is_retryable(RateLimitedError("too many requests"))
    True
    >>> is_retryable(BadRequestError("invalid payload"))
    False
    """
    if isinstance(error, (NetworkError, AptosTimeoutError)):
        return True
    if isinstance(error, ApiError):
        return is_retryable_status_code(error.status_code, config)
    return False


# ---------------------------------------------------------------------------
# Core retry function
# ---------------------------------------------------------------------------


async def with_retry(
    fn: Callable[..., Awaitable[T]],
    *args: Any,
    config: RetryConfig = DEFAULT_RETRY_CONFIG,
    **kwargs: Any,
) -> T:
    """
    Execute an async callable with exponential backoff retry on transient errors.

    The callable *fn* is invoked with *args* and *kwargs*.  If it raises a
    retryable exception (see :func:`is_retryable`), the call is retried up to
    ``config.max_retries`` additional times, waiting an exponentially growing
    delay between attempts.

    If the exception is **not** retryable, or if the maximum number of retries
    has been exhausted, the most recent exception is re-raised immediately.

    Backoff calculation
    -------------------
    For attempt index ``i`` (0-based, where 0 is the first retry)::

        backoff_ms = min(
            initial_backoff_ms * (backoff_multiplier ** i),
            max_backoff_ms,
        )

    If ``jitter`` is enabled, the final sleep is::

        sleep_ms = random.uniform(0, backoff_ms)

    This adds randomness to prevent all clients from retrying in lock-step
    (thundering-herd problem).

    Parameters
    ----------
    fn:
        An async callable to invoke.
    *args:
        Positional arguments forwarded to *fn*.
    config:
        Retry configuration.  Defaults to :data:`DEFAULT_RETRY_CONFIG`.
    **kwargs:
        Keyword arguments forwarded to *fn*.

    Returns
    -------
    T
        The return value of *fn* on success.

    Raises
    ------
    Exception
        Re-raises the last exception from *fn*, either because it is not
        retryable or because all retries were exhausted.

    Examples
    --------
    Wrap a client method call::

        async with RestClient(Network.TESTNET.fullnode_url) as client:
            info = await with_retry(client.get_ledger_info)

    Pass arguments through::

        balance = await with_retry(client.account_balance, address)

    Override the config::

        config = RetryConfig(max_retries=5, initial_backoff_ms=50)
        result = await with_retry(client.submit_bcs_transaction, txn, config=config)
    """
    last_error: Exception | None = None

    for attempt in range(config.max_retries + 1):
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:
            if not is_retryable(exc, config) or attempt == config.max_retries:
                raise
            last_error = exc

            # Exponential backoff: grows as initial * multiplier^attempt
            backoff_ms = min(
                config.initial_backoff_ms * (config.backoff_multiplier**attempt),
                config.max_backoff_ms,
            )

            # Full-jitter: uniform sample in [0, backoff_ms] to spread load
            if config.jitter:
                backoff_ms = random.uniform(0, backoff_ms)

            await asyncio.sleep(backoff_ms / 1000.0)

    # Unreachable: the loop either returns or raises inside the except block.
    # This branch satisfies the type-checker.
    assert last_error is not None
    raise last_error
