"""Error hierarchy for the Aptos Python SDK v2."""

from __future__ import annotations


class AptosError(Exception):
    """Base exception for all Aptos SDK errors."""


# --- API errors ---


class ApiError(AptosError):
    """Raised when the Aptos REST API returns an error response."""

    def __init__(self, message: str, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"API error {status_code}: {message}")


class AccountNotFoundError(ApiError):
    """Raised when an account does not exist on-chain."""

    def __init__(self, address: str) -> None:
        super().__init__(f"Account not found: {address}", 404)


class ResourceNotFoundError(ApiError):
    """Raised when a resource does not exist on an account."""

    def __init__(self, address: str, resource_type: str) -> None:
        super().__init__(f"Resource {resource_type} not found on {address}", 404)


# --- Transaction errors ---


class TransactionError(AptosError):
    """Base exception for transaction-related errors."""


class TransactionTimeoutError(TransactionError):
    """Raised when waiting for a transaction exceeds the timeout."""

    def __init__(self, txn_hash: str) -> None:
        self.txn_hash = txn_hash
        super().__init__(f"Transaction {txn_hash} timed out")


class TransactionFailedError(TransactionError):
    """Raised when a transaction is committed but failed execution."""

    def __init__(self, txn_hash: str, vm_status: str) -> None:
        self.txn_hash = txn_hash
        self.vm_status = vm_status
        super().__init__(f"Transaction {txn_hash} failed: {vm_status}")


# --- BCS errors ---


class BcsError(AptosError):
    """Base exception for BCS serialization/deserialization errors."""


class BcsSerializationError(BcsError):
    """Raised when BCS serialization fails due to invalid input."""


class BcsDeserializationError(BcsError):
    """Raised when BCS deserialization fails."""


# --- Crypto errors ---


class CryptoError(AptosError):
    """Base exception for cryptographic errors."""


class InvalidKeyError(CryptoError):
    """Raised when a cryptographic key is invalid or has an unexpected format."""


class InvalidSignatureError(CryptoError):
    """Raised when a cryptographic signature is invalid."""


class InvalidMnemonicError(CryptoError):
    """Raised when a mnemonic phrase is invalid."""


# --- Type errors ---


class InvalidAddressError(AptosError):
    """Raised when an account address string is malformed."""


class InvalidTypeTagError(AptosError):
    """Raised when a type tag string cannot be parsed."""
