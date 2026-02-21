# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for aptos_sdk.errors — error hierarchy and categories."""

import pytest

from aptos_sdk.errors import (
    ApiError,
    AptosError,
    AptosTimeoutError,
    BadRequestError,
    BcsError,
    ConflictError,
    ConnectionFailedError,
    CryptoError,
    DuplicateTransactionError,
    EphemeralKeyExpiredError,
    ErrorCategory,
    InsufficientBalanceError,
    InternalServerError,
    InvalidAddressError,
    InvalidExpirationError,
    InvalidHexError,
    InvalidInputError,
    InvalidLengthError,
    InvalidModuleIdError,
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    InvalidSignatureError,
    InvalidStateError,
    InvalidStructTagError,
    InvalidTypeTagError,
    JsonError,
    KeyGenerationFailedError,
    MissingChainIdError,
    MissingPayloadError,
    MissingSenderError,
    MissingSequenceNumberError,
    NetworkError,
    NotFoundError,
    ParseError,
    RateLimitedError,
    SequenceNumberMismatchError,
    SerializationError,
    TransactionExpiredError,
    TransactionSubmissionError,
    VerificationFailedError,
    VmError,
)


class TestErrorCategory:
    def test_category_values(self):
        assert ErrorCategory.PARSE.value == "parse"
        assert ErrorCategory.CRYPTO.value == "crypto"
        assert ErrorCategory.SERIALIZATION.value == "serialization"
        assert ErrorCategory.NETWORK.value == "network"
        assert ErrorCategory.API.value == "api"
        assert ErrorCategory.TIMEOUT.value == "timeout"
        assert ErrorCategory.NOT_FOUND.value == "not_found"
        assert ErrorCategory.INVALID_STATE.value == "invalid_state"
        assert ErrorCategory.INVALID_INPUT.value == "invalid_input"
        assert ErrorCategory.UNAUTHORIZED.value == "unauthorized"
        assert ErrorCategory.RATE_LIMITED.value == "rate_limited"
        assert ErrorCategory.INTERNAL.value == "internal"

    def test_category_count(self):
        assert len(ErrorCategory) == 12


class TestAptosError:
    def test_message(self):
        err = AptosError("something failed")
        assert str(err) == "something failed"

    def test_error_code(self):
        err = AptosError("fail", error_code="ERR_001")
        assert err.error_code == "ERR_001"

    def test_no_error_code(self):
        err = AptosError("fail")
        assert err.error_code is None

    def test_cause_chain(self):
        cause = ValueError("root cause")
        err = AptosError("fail", cause=cause)
        assert err.__cause__ is cause

    def test_default_category(self):
        err = AptosError("fail")
        assert err.category == ErrorCategory.INTERNAL

    def test_repr(self):
        err = AptosError("fail", error_code="CODE")
        r = repr(err)
        assert "AptosError" in r
        assert "fail" in r
        assert "CODE" in r
        assert "internal" in r

    def test_isinstance_exception(self):
        assert issubclass(AptosError, Exception)


class TestCategoryParentClasses:
    def test_parse_error(self):
        assert issubclass(ParseError, AptosError)
        assert ParseError.category == ErrorCategory.PARSE

    def test_crypto_error(self):
        assert issubclass(CryptoError, AptosError)
        assert CryptoError.category == ErrorCategory.CRYPTO

    def test_serialization_error(self):
        assert issubclass(SerializationError, AptosError)
        assert SerializationError.category == ErrorCategory.SERIALIZATION

    def test_network_error(self):
        assert issubclass(NetworkError, AptosError)
        assert NetworkError.category == ErrorCategory.NETWORK

    def test_api_error(self):
        assert issubclass(ApiError, AptosError)
        assert ApiError.category == ErrorCategory.API

    def test_timeout_error(self):
        assert issubclass(AptosTimeoutError, AptosError)
        assert AptosTimeoutError.category == ErrorCategory.TIMEOUT

    def test_invalid_state_error(self):
        assert issubclass(InvalidStateError, AptosError)
        assert InvalidStateError.category == ErrorCategory.INVALID_STATE

    def test_invalid_input_error(self):
        assert issubclass(InvalidInputError, AptosError)
        assert InvalidInputError.category == ErrorCategory.INVALID_INPUT

    def test_transaction_submission_error(self):
        assert issubclass(TransactionSubmissionError, AptosError)
        assert TransactionSubmissionError.category == ErrorCategory.API


class TestApiError:
    def test_status_code(self):
        err = ApiError("bad", status_code=400)
        assert err.status_code == 400

    def test_vm_error_code(self):
        err = ApiError("vm fail", status_code=400, vm_error_code=42)
        assert err.vm_error_code == 42

    def test_no_vm_error_code(self):
        err = ApiError("bad", status_code=400)
        assert err.vm_error_code is None

    def test_repr(self):
        err = ApiError("bad", status_code=400, vm_error_code=99, error_code="VM_ERR")
        r = repr(err)
        assert "400" in r
        assert "99" in r
        assert "VM_ERR" in r


class TestInvalidLengthError:
    def test_expected_actual(self):
        err = InvalidLengthError("bad len", expected=32, actual=64)
        assert err.expected == 32
        assert err.actual == 64

    def test_repr(self):
        err = InvalidLengthError("bad len", expected=32, actual=64)
        r = repr(err)
        assert "32" in r
        assert "64" in r


class TestParseErrorSubclasses:
    @pytest.mark.parametrize(
        "cls",
        [
            InvalidAddressError,
            InvalidHexError,
            InvalidLengthError,
            InvalidTypeTagError,
            InvalidStructTagError,
            InvalidModuleIdError,
        ],
    )
    def test_inherits_parse_error(self, cls):
        assert issubclass(cls, ParseError)
        assert issubclass(cls, AptosError)


class TestCryptoErrorSubclasses:
    @pytest.mark.parametrize(
        "cls",
        [
            InvalidPrivateKeyError,
            InvalidPublicKeyError,
            InvalidSignatureError,
            VerificationFailedError,
            KeyGenerationFailedError,
        ],
    )
    def test_inherits_crypto_error(self, cls):
        assert issubclass(cls, CryptoError)
        assert issubclass(cls, AptosError)


class TestSerializationSubclasses:
    def test_bcs_error(self):
        assert issubclass(BcsError, SerializationError)

    def test_json_error(self):
        assert issubclass(JsonError, SerializationError)


class TestNetworkSubclasses:
    def test_connection_failed(self):
        assert issubclass(ConnectionFailedError, NetworkError)


class TestApiSubclasses:
    @pytest.mark.parametrize(
        "cls",
        [
            BadRequestError,
            NotFoundError,
            ConflictError,
            RateLimitedError,
            InternalServerError,
            VmError,
        ],
    )
    def test_inherits_api_error(self, cls):
        assert issubclass(cls, ApiError)
        assert issubclass(cls, AptosError)


class TestInvalidStateSubclasses:
    def test_ephemeral_key_expired(self):
        assert issubclass(EphemeralKeyExpiredError, InvalidStateError)


class TestInvalidInputSubclasses:
    @pytest.mark.parametrize(
        "cls",
        [
            MissingSenderError,
            MissingSequenceNumberError,
            MissingPayloadError,
            MissingChainIdError,
            InvalidExpirationError,
        ],
    )
    def test_inherits_invalid_input(self, cls):
        assert issubclass(cls, InvalidInputError)
        assert issubclass(cls, AptosError)


class TestTransactionSubmissionSubclasses:
    @pytest.mark.parametrize(
        "cls",
        [
            SequenceNumberMismatchError,
            InsufficientBalanceError,
            TransactionExpiredError,
            DuplicateTransactionError,
        ],
    )
    def test_inherits_submission_error(self, cls):
        assert issubclass(cls, TransactionSubmissionError)
        assert issubclass(cls, AptosError)


class TestErrorCatching:
    def test_catch_aptos_error(self):
        with pytest.raises(AptosError):
            raise InvalidAddressError("bad")

    def test_catch_parse_error(self):
        with pytest.raises(ParseError):
            raise InvalidHexError("bad hex")

    def test_catch_api_error(self):
        with pytest.raises(ApiError):
            raise NotFoundError("missing")
