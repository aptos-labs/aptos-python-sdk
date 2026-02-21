# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Spec-aligned error hierarchy for the Aptos Python SDK (Spec 08).

All SDK exceptions inherit from :class:`AptosError`, which carries an
:class:`ErrorCategory` discriminant, an optional machine-readable
``error_code`` string, and an optional ``cause`` (chained exception).

Hierarchy
---------
AptosError
├── ParseError
│   ├── InvalidAddressError
│   ├── InvalidHexError
│   ├── InvalidLengthError
│   ├── InvalidTypeTagError
│   ├── InvalidStructTagError
│   └── InvalidModuleIdError
├── CryptoError
│   ├── InvalidPrivateKeyError
│   ├── InvalidPublicKeyError
│   ├── InvalidSignatureError
│   ├── VerificationFailedError
│   └── KeyGenerationFailedError
├── SerializationError
│   ├── BcsError
│   └── JsonError
├── NetworkError
│   └── ConnectionFailedError
├── ApiError
│   ├── BadRequestError         (HTTP 400)
│   ├── NotFoundError           (HTTP 404)
│   ├── ConflictError           (HTTP 409)
│   ├── RateLimitedError        (HTTP 429)
│   ├── InternalServerError     (HTTP 5xx)
│   └── VmError
├── AptosTimeoutError
├── InvalidStateError
│   └── EphemeralKeyExpiredError
├── InvalidInputError
│   ├── MissingSenderError
│   ├── MissingSequenceNumberError
│   ├── MissingPayloadError
│   ├── MissingChainIdError
│   └── InvalidExpirationError
└── TransactionSubmissionError
    ├── SequenceNumberMismatchError
    ├── InsufficientBalanceError
    ├── TransactionExpiredError
    └── DuplicateTransactionError
"""

from enum import Enum

# ---------------------------------------------------------------------------
# Error categories
# ---------------------------------------------------------------------------


class ErrorCategory(Enum):
    """
    Top-level discriminant attached to every :class:`AptosError`.

    Used by retry strategies and error-handling middleware to decide how to
    react to a failure without inspecting concrete exception types.

    Values
    ------
    PARSE
        Input could not be parsed into the expected type.
    CRYPTO
        A cryptographic operation failed.
    SERIALIZATION
        BCS or JSON encoding / decoding failed.
    NETWORK
        A network-level failure occurred before receiving an HTTP response.
    API
        The server returned an error HTTP response.
    TIMEOUT
        An operation exceeded its deadline.
    NOT_FOUND
        The requested resource does not exist (HTTP 404 equivalent).
    INVALID_STATE
        The SDK was used in an invalid state (e.g. expired key).
    INVALID_INPUT
        Caller-supplied inputs are missing or logically invalid.
    UNAUTHORIZED
        The request lacks valid authentication credentials (HTTP 401/403).
    RATE_LIMITED
        The server is rate-limiting requests (HTTP 429 equivalent).
    INTERNAL
        An unexpected internal error within the SDK.
    """

    PARSE = "parse"
    CRYPTO = "crypto"
    SERIALIZATION = "serialization"
    NETWORK = "network"
    API = "api"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    INVALID_STATE = "invalid_state"
    INVALID_INPUT = "invalid_input"
    UNAUTHORIZED = "unauthorized"
    RATE_LIMITED = "rate_limited"
    INTERNAL = "internal"


# ---------------------------------------------------------------------------
# Base exception
# ---------------------------------------------------------------------------


class AptosError(Exception):
    """
    Base exception for all Aptos SDK errors.

    Every SDK exception inherits from this class.  Callers that want to
    handle any SDK error generically can catch ``AptosError``; callers that
    want to distinguish failure modes should catch specific subtypes or
    compare ``error.category``.

    Parameters
    ----------
    message:
        Human-readable description of the error.
    error_code:
        Optional machine-readable identifier (e.g. ``"ACCOUNT_NOT_FOUND"``).
        Sourced from API response bodies where available.
    cause:
        Optional original exception that triggered this error.  Stored as
        ``__cause__`` so standard Python traceback chaining works correctly.

    Attributes
    ----------
    category : ErrorCategory
        Discriminant indicating the broad failure category.  Set at the
        class level by each concrete subclass; ``INTERNAL`` by default.
    error_code : str | None
        Machine-readable code supplied at construction time.
    """

    # Subclasses must override this class-level attribute.
    category: ErrorCategory = ErrorCategory.INTERNAL

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code: str | None = error_code
        if cause is not None:
            self.__cause__ = cause

    def __repr__(self) -> str:
        parts = [f"{type(self).__name__}({str(self)!r}"]
        if self.error_code is not None:
            parts.append(f", error_code={self.error_code!r}")
        parts.append(f", category={self.category.value!r}")
        parts.append(")")
        return "".join(parts)


# ---------------------------------------------------------------------------
# Category parent classes
# ---------------------------------------------------------------------------


class ParseError(AptosError):
    """
    Raised when input cannot be parsed into the expected type.

    Examples: malformed hex strings, invalid account addresses, bad type-tag
    expressions, unrecognised module identifiers.
    """

    category = ErrorCategory.PARSE


class CryptoError(AptosError):
    """
    Raised when a cryptographic operation fails.

    Examples: key bytes of the wrong length, a signature that does not verify,
    or failure during key-pair generation.
    """

    category = ErrorCategory.CRYPTO


class SerializationError(AptosError):
    """
    Raised when BCS or JSON serialization / deserialization fails.

    Examples: BCS buffer underflow, value out of range for the target integer
    type, unexpected structure in a JSON API response.
    """

    category = ErrorCategory.SERIALIZATION


class NetworkError(AptosError):
    """
    Raised when a network-level failure occurs before an HTTP response is
    received (connection refused, DNS failure, TLS handshake error, etc.).

    Network errors are generally retryable.
    """

    category = ErrorCategory.NETWORK


class ApiError(AptosError):
    """
    Raised when the Aptos fullnode or faucet returns an error HTTP response.

    Parameters
    ----------
    message:
        Human-readable description of the error.
    status_code:
        HTTP status code returned by the server.
    vm_error_code:
        Optional numeric VM abort code (Move abort codes) for VM-level
        failures.  ``None`` when the error is not a VM abort.
    error_code:
        Optional machine-readable identifier from the API response body.
    cause:
        Optional original exception.

    Attributes
    ----------
    status_code : int
        HTTP status code from the server response.
    vm_error_code : int | None
        Move VM abort code, if applicable.
    error_code : str | None
        Machine-readable error identifier from the API response body.
    """

    category = ErrorCategory.API

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        vm_error_code: int | None = None,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, cause=cause)
        self.status_code: int = status_code
        self.vm_error_code: int | None = vm_error_code

    def __repr__(self) -> str:
        parts = [
            f"{type(self).__name__}({str(self)!r}",
            f", status_code={self.status_code!r}",
        ]
        if self.vm_error_code is not None:
            parts.append(f", vm_error_code={self.vm_error_code!r}")
        if self.error_code is not None:
            parts.append(f", error_code={self.error_code!r}")
        parts.append(")")
        return "".join(parts)


class AptosTimeoutError(AptosError):
    """
    Raised when a wait-for-transaction or network request exceeds its deadline.

    Named ``AptosTimeoutError`` rather than ``TimeoutError`` to avoid
    shadowing the Python built-in ``TimeoutError``.  Timeout errors are
    generally retryable.
    """

    category = ErrorCategory.TIMEOUT


class InvalidStateError(AptosError):
    """
    Raised when the SDK is used in an invalid or inconsistent state.

    Examples: an expired ephemeral key, calling a method that requires
    prior initialisation, or an object in a terminal state being reused.
    """

    category = ErrorCategory.INVALID_STATE


class InvalidInputError(AptosError):
    """
    Raised when caller-supplied inputs are missing or logically invalid,
    before any network or cryptographic operation is attempted.

    These errors are non-retryable; the caller must fix the input.
    """

    category = ErrorCategory.INVALID_INPUT


class TransactionSubmissionError(AptosError):
    """
    Raised when a transaction submission fails for a blockchain-level reason
    (sequence number mismatch, insufficient balance, expiry, duplicate) as
    opposed to a transport or parse failure.

    These errors are typically non-retryable without modifying the transaction.
    """

    category = ErrorCategory.API


# ---------------------------------------------------------------------------
# ParseError subclasses
# ---------------------------------------------------------------------------


class InvalidAddressError(ParseError):
    """
    Raised when a string cannot be parsed as a valid Aptos ``AccountAddress``.

    A valid address is a 32-byte value expressed as a 64-character hex string
    (optionally ``0x``-prefixed), or a short-form special address such as
    ``0x1`` through ``0xf``.
    """


class InvalidHexError(ParseError):
    """
    Raised when a string contains characters that are not valid hexadecimal
    digits (``[0-9a-fA-F]``), or when the ``0x`` prefix is expected but absent.
    """


class InvalidLengthError(ParseError):
    """
    Raised when a binary value has an unexpected number of bytes.

    Parameters
    ----------
    message:
        Human-readable description of the error.
    expected:
        The expected byte length, if statically known.
    actual:
        The actual byte length that was observed.
    error_code:
        Optional machine-readable identifier.
    cause:
        Optional original exception.

    Attributes
    ----------
    expected : int | None
    actual : int | None
    """

    def __init__(
        self,
        message: str,
        *,
        expected: int | None = None,
        actual: int | None = None,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, cause=cause)
        self.expected: int | None = expected
        self.actual: int | None = actual

    def __repr__(self) -> str:
        parts = [f"InvalidLengthError({str(self)!r}"]
        if self.expected is not None:
            parts.append(f", expected={self.expected!r}")
        if self.actual is not None:
            parts.append(f", actual={self.actual!r}")
        parts.append(")")
        return "".join(parts)


class InvalidTypeTagError(ParseError):
    """
    Raised when a type-tag string cannot be parsed into a :class:`TypeTag`.

    Examples of invalid type tags: ``"u65"``, ``"0x1::coin::"``, or a
    string with unbalanced angle brackets.
    """


class InvalidStructTagError(ParseError):
    """
    Raised when a struct-tag string cannot be parsed into a ``StructTag``.

    A valid struct tag has the canonical form
    ``<address>::<module>::<name>[<type_args>]``.
    """


class InvalidModuleIdError(ParseError):
    """
    Raised when a Move module identifier string cannot be parsed.

    A valid module ID has the form ``<address>::<module>``,
    e.g. ``"0x1::aptos_account"``.
    """


# ---------------------------------------------------------------------------
# CryptoError subclasses
# ---------------------------------------------------------------------------


class InvalidPrivateKeyError(CryptoError):
    """
    Raised when private key bytes are the wrong length or represent a
    scalar that is invalid for the target elliptic curve.
    """


class InvalidPublicKeyError(CryptoError):
    """
    Raised when public key bytes are the wrong length or fail curve
    point-validation.
    """


class InvalidSignatureError(CryptoError):
    """
    Raised when signature bytes are the wrong length or are otherwise
    structurally invalid, prior to any verification attempt.
    """


class VerificationFailedError(CryptoError):
    """
    Raised when a cryptographic signature does not verify against the
    provided message and public key.
    """


class KeyGenerationFailedError(CryptoError):
    """
    Raised when key-pair generation fails, for example due to insufficient
    system entropy.
    """


# ---------------------------------------------------------------------------
# SerializationError subclasses
# ---------------------------------------------------------------------------


class BcsError(SerializationError):
    """
    Raised when BCS (Binary Canonical Serialization) encoding or decoding
    fails.

    Examples: buffer underflow during deserialization, a value that is out
    of range for the target integer type, ULEB128 overflow.
    """


class JsonError(SerializationError):
    """
    Raised when JSON encoding or decoding fails.

    Examples: the API response body is not valid JSON, or the JSON structure
    does not match the expected schema.
    """


# ---------------------------------------------------------------------------
# NetworkError subclasses
# ---------------------------------------------------------------------------


class ConnectionFailedError(NetworkError):
    """
    Raised when a TCP/TLS connection to the fullnode or faucet cannot be
    established (connection refused, DNS resolution failure, TLS handshake
    error, etc.).
    """


# ---------------------------------------------------------------------------
# ApiError subclasses
# ---------------------------------------------------------------------------


class BadRequestError(ApiError):
    """
    Raised when the server returns HTTP 400 Bad Request.

    Indicates a client-side error in the request payload; this error is
    non-retryable without correcting the request.
    """

    def __init__(
        self,
        message: str,
        *,
        vm_error_code: int | None = None,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=400,
            vm_error_code=vm_error_code,
            error_code=error_code,
            cause=cause,
        )


class NotFoundError(ApiError):
    """
    Raised when the server returns HTTP 404 Not Found.

    Examples: querying an account address that has not been created on-chain,
    or fetching a transaction version that does not exist yet.
    """

    category = ErrorCategory.NOT_FOUND

    def __init__(
        self,
        message: str,
        *,
        vm_error_code: int | None = None,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=404,
            vm_error_code=vm_error_code,
            error_code=error_code,
            cause=cause,
        )


class ConflictError(ApiError):
    """
    Raised when the server returns HTTP 409 Conflict.

    Typically indicates a transaction that conflicts with an already-committed
    or mempool-pending transaction (e.g. duplicate sequence number).
    """

    def __init__(
        self,
        message: str,
        *,
        vm_error_code: int | None = None,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=409,
            vm_error_code=vm_error_code,
            error_code=error_code,
            cause=cause,
        )


class RateLimitedError(ApiError):
    """
    Raised when the server returns HTTP 429 Too Many Requests.

    The request should be retried after an appropriate back-off delay.
    """

    category = ErrorCategory.RATE_LIMITED

    def __init__(
        self,
        message: str,
        *,
        vm_error_code: int | None = None,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=429,
            vm_error_code=vm_error_code,
            error_code=error_code,
            cause=cause,
        )


class InternalServerError(ApiError):
    """
    Raised when the server returns an HTTP 5xx status code.

    Indicates a transient server-side failure; typically retryable.

    Parameters
    ----------
    status_code:
        The exact 5xx status code (500, 502, 503, etc.).  Defaults to 500.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 500,
        vm_error_code: int | None = None,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            vm_error_code=vm_error_code,
            error_code=error_code,
            cause=cause,
        )


class VmError(ApiError):
    """
    Raised when a submitted transaction fails with a Move VM abort or
    execution error.

    The ``vm_error_code`` attribute holds the numeric abort code from the
    Move module.  The ``error_code`` field from the response body may carry a
    symbolic name such as ``"EINSUFFICIENT_BALANCE"``.

    Parameters
    ----------
    status_code:
        HTTP status code from the server (typically 400).  Defaults to 400.
    vm_error_code:
        The numeric Move VM abort code.
    error_code:
        Optional symbolic name for the abort code from the API response.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 400,
        vm_error_code: int | None = None,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            vm_error_code=vm_error_code,
            error_code=error_code,
            cause=cause,
        )


# ---------------------------------------------------------------------------
# InvalidStateError subclasses
# ---------------------------------------------------------------------------


class EphemeralKeyExpiredError(InvalidStateError):
    """
    Raised when an ephemeral key used in keyless (OIDB) transactions has
    passed its expiry timestamp and can no longer be used for signing.
    """


# ---------------------------------------------------------------------------
# InvalidInputError subclasses
# ---------------------------------------------------------------------------


class MissingSenderError(InvalidInputError):
    """
    Raised when a transaction builder is asked to build a transaction without
    a sender address having been set.
    """


class MissingSequenceNumberError(InvalidInputError):
    """
    Raised when a transaction builder is asked to build a transaction without
    a sequence number having been set.
    """


class MissingPayloadError(InvalidInputError):
    """
    Raised when a transaction builder is asked to build a transaction without
    a payload (entry function, script, or multisig) having been set.
    """


class MissingChainIdError(InvalidInputError):
    """
    Raised when a transaction builder is asked to build a transaction without
    a chain ID having been set.
    """


class InvalidExpirationError(InvalidInputError):
    """
    Raised when the expiration timestamp supplied for a transaction is in the
    past or otherwise invalid (e.g. zero or negative).
    """


# ---------------------------------------------------------------------------
# TransactionSubmissionError subclasses
# ---------------------------------------------------------------------------


class SequenceNumberMismatchError(TransactionSubmissionError):
    """
    Raised when the sequence number in the submitted transaction does not
    match the account's current on-chain sequence number.

    The transaction must be rebuilt with the correct sequence number.
    """


class InsufficientBalanceError(TransactionSubmissionError):
    """
    Raised when the account does not hold enough APT to cover the maximum
    gas fee for the transaction (``max_gas_amount * gas_unit_price``).
    """


class TransactionExpiredError(TransactionSubmissionError):
    """
    Raised when the transaction's ``expiration_timestamp_secs`` has already
    passed by the time the transaction is evaluated.
    """


class DuplicateTransactionError(TransactionSubmissionError):
    """
    Raised when an identical transaction (same hash) has already been
    submitted to the mempool or committed on-chain.
    """
