# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Exception hierarchy for the Aptos Python SDK.

All SDK-specific exceptions inherit from AptosError, allowing users to catch
all SDK errors with a single except clause if desired.

Example:
    try:
        await client.account(address)
    except AccountNotFound:
        print("Account does not exist")
    except ApiError as e:
        print(f"API error {e.status_code}: {e}")
    except AptosError:
        print("Some other SDK error occurred")
"""

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from aptos_sdk.account_address import AccountAddress


class AptosError(Exception):
    """Base exception for all Aptos SDK errors."""

    pass


# =============================================================================
# API Errors
# =============================================================================


class ApiError(AptosError):
    """
    The API returned a non-success status code.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code from the API response.
    """

    def __init__(self, message: str, status_code: int):
        self.message = message
        self.status_code = status_code
        super().__init__(f"API Error ({status_code}): {message}")

    def __repr__(self) -> str:
        return f"ApiError(message={self.message!r}, status_code={self.status_code})"


class AccountNotFound(ApiError):
    """
    The specified account was not found on chain.

    This typically means the account has not been created yet (no transactions
    have been sent to or from it).

    Attributes:
        address: The account address that was not found.
    """

    def __init__(self, address: "AccountAddress"):
        self.address = address
        super().__init__(
            f"Account not found: {address}. The account may not exist on chain yet.",
            404,
        )


class ResourceNotFound(ApiError):
    """
    The specified resource was not found on an account.

    Attributes:
        resource_type: The Move resource type that was not found.
        address: Optional account address where the resource was expected.
    """

    def __init__(
        self, resource_type: str, address: Optional["AccountAddress"] = None
    ):
        self.resource_type = resource_type
        self.address = address
        addr_str = f" on account {address}" if address else ""
        super().__init__(f"Resource not found: {resource_type}{addr_str}", 404)


class ModuleNotFound(ApiError):
    """The specified module was not found on an account."""

    def __init__(self, module_name: str, address: Optional["AccountAddress"] = None):
        self.module_name = module_name
        self.address = address
        addr_str = f" on account {address}" if address else ""
        super().__init__(f"Module not found: {module_name}{addr_str}", 404)


# =============================================================================
# Transaction Errors
# =============================================================================


class TransactionError(AptosError):
    """Base class for transaction-related errors."""

    pass


class TransactionTimeout(TransactionError):
    """
    Transaction did not complete within the timeout period.

    Attributes:
        txn_hash: The transaction hash that timed out.
        timeout_seconds: The timeout duration in seconds.
    """

    def __init__(self, txn_hash: str, timeout_seconds: int):
        self.txn_hash = txn_hash
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Transaction {txn_hash} timed out after {timeout_seconds} seconds. "
            "The transaction may still be pending."
        )


class TransactionFailed(TransactionError):
    """
    Transaction failed during execution.

    Attributes:
        txn_hash: The transaction hash that failed.
        vm_status: The VM status/error code from execution.
    """

    def __init__(self, txn_hash: str, vm_status: str):
        self.txn_hash = txn_hash
        self.vm_status = vm_status
        super().__init__(f"Transaction {txn_hash} failed: {vm_status}")


class SimulationError(TransactionError):
    """Transaction simulation failed."""

    def __init__(self, message: str, vm_status: Optional[str] = None):
        self.vm_status = vm_status
        status_str = f" (VM status: {vm_status})" if vm_status else ""
        super().__init__(f"Simulation failed: {message}{status_str}")


# =============================================================================
# BCS Errors
# =============================================================================


class BcsError(AptosError):
    """Base class for BCS serialization/deserialization errors."""

    pass


class DeserializationError(BcsError):
    """
    Failed to deserialize BCS data.

    Attributes:
        message: Description of what went wrong.
        position: Optional byte position where the error occurred.
    """

    def __init__(self, message: str, position: Optional[int] = None):
        self.position = position
        pos_str = f" at position {position}" if position is not None else ""
        super().__init__(f"BCS deserialization error{pos_str}: {message}")


class SerializationError(BcsError):
    """Failed to serialize data to BCS format."""

    def __init__(self, message: str):
        super().__init__(f"BCS serialization error: {message}")


class InvalidTypeTag(BcsError):
    """Invalid or unrecognized type tag encountered."""

    def __init__(self, tag_value: int):
        self.tag_value = tag_value
        super().__init__(f"Invalid type tag value: {tag_value}")


# =============================================================================
# Cryptography Errors
# =============================================================================


class CryptoError(AptosError):
    """Base class for cryptographic operation errors."""

    pass


class InvalidSignature(CryptoError):
    """The provided signature is invalid or verification failed."""

    pass


class InvalidPrivateKey(CryptoError):
    """The provided private key is invalid or malformed."""

    def __init__(self, message: str = "Invalid private key format"):
        super().__init__(message)


class InvalidPublicKey(CryptoError):
    """The provided public key is invalid or malformed."""

    def __init__(self, message: str = "Invalid public key format"):
        super().__init__(message)


# =============================================================================
# Address Errors
# =============================================================================


class AddressError(AptosError):
    """Base class for account address errors."""

    pass


class InvalidAddress(AddressError):
    """The provided address string is invalid."""

    def __init__(self, address_str: str, reason: Optional[str] = None):
        self.address_str = address_str
        reason_str = f": {reason}" if reason else ""
        super().__init__(f"Invalid address '{address_str}'{reason_str}")


# =============================================================================
# Configuration Errors
# =============================================================================


class ConfigurationError(AptosError):
    """Invalid SDK configuration."""

    pass

