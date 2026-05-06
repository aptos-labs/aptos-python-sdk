"""Unit tests for error hierarchy."""

from aptos_sdk_v2.errors import (
    AccountNotFoundError,
    ApiError,
    AptosError,
    BcsDeserializationError,
    BcsError,
    BcsSerializationError,
    CryptoError,
    InvalidAddressError,
    InvalidKeyError,
    InvalidMnemonicError,
    InvalidSignatureError,
    InvalidTypeTagError,
    ResourceNotFoundError,
    TransactionError,
    TransactionFailedError,
    TransactionTimeoutError,
)


class TestErrorHierarchy:
    def test_api_error(self):
        err = ApiError("bad request", 400)
        assert err.status_code == 400
        assert "400" in str(err)
        assert isinstance(err, AptosError)

    def test_account_not_found(self):
        err = AccountNotFoundError("0x1")
        assert err.status_code == 404
        assert "0x1" in str(err)
        assert isinstance(err, ApiError)

    def test_resource_not_found(self):
        err = ResourceNotFoundError("0x1", "0x1::coin::CoinStore")
        assert err.status_code == 404
        assert "CoinStore" in str(err)

    def test_transaction_timeout(self):
        err = TransactionTimeoutError("0xabc")
        assert err.txn_hash == "0xabc"
        assert "timed out" in str(err)
        assert isinstance(err, TransactionError)

    def test_transaction_failed(self):
        err = TransactionFailedError("0xdef", "ABORT")
        assert err.txn_hash == "0xdef"
        assert err.vm_status == "ABORT"
        assert "failed" in str(err)
        assert isinstance(err, TransactionError)

    def test_bcs_errors(self):
        assert isinstance(BcsSerializationError(), BcsError)
        assert isinstance(BcsDeserializationError(), BcsError)
        assert isinstance(BcsError(), AptosError)

    def test_crypto_errors(self):
        assert isinstance(InvalidKeyError(), CryptoError)
        assert isinstance(InvalidSignatureError(), CryptoError)
        assert isinstance(InvalidMnemonicError(), CryptoError)
        assert isinstance(CryptoError(), AptosError)

    def test_type_errors(self):
        assert isinstance(InvalidAddressError(), AptosError)
        assert isinstance(InvalidTypeTagError(), AptosError)
