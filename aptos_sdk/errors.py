# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
V1 error hierarchy with compatibility bridges to v2 errors.

The v1 error classes are preserved so that existing ``except`` clauses continue
to work.  ``SerializationError`` and ``DeserializationError`` now additionally
inherit from the corresponding v2 BCS error classes, which means they are caught
by both ``except v1.BcsError`` and ``except v2.BcsError`` handlers.
"""

import importlib.util as _importlib_util
import os as _os

# Import v2 errors directly from the file to avoid triggering the heavy
# v2/__init__.py which pulls in crypto dependencies.
_v2_errors_path = _os.path.join(_os.path.dirname(__file__), "v2", "errors.py")
_spec = _importlib_util.spec_from_file_location("aptos_sdk.v2.errors", _v2_errors_path)
_v2_errors = _importlib_util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_v2_errors)  # type: ignore[union-attr]

AptosError = _v2_errors.AptosError
ApiError = _v2_errors.ApiError
AccountNotFoundError = _v2_errors.AccountNotFoundError
ResourceNotFoundError = _v2_errors.ResourceNotFoundError
TransactionError = _v2_errors.TransactionError
TransactionTimeoutError = _v2_errors.TransactionTimeoutError
TransactionFailedError = _v2_errors.TransactionFailedError
BcsSerializationError = _v2_errors.BcsSerializationError
BcsDeserializationError = _v2_errors.BcsDeserializationError
V2BcsError = _v2_errors.BcsError
CryptoError = _v2_errors.CryptoError
V2InvalidKeyError = _v2_errors.InvalidKeyError
V2InvalidSignatureError = _v2_errors.InvalidSignatureError
InvalidMnemonicError = _v2_errors.InvalidMnemonicError
InvalidAddressError = _v2_errors.InvalidAddressError
InvalidTypeTagError = _v2_errors.InvalidTypeTagError


# ---------------------------------------------------------------------------
# V1 base classes (unchanged)
# ---------------------------------------------------------------------------

class AptosSDKError(Exception):
    """Base exception for the Aptos SDK."""


class BcsError(AptosSDKError):
    """Base exception for BCS serialization/deserialization errors."""


class InvalidKeyError(AptosSDKError):
    """Raised when a cryptographic key is invalid or has an unexpected format."""


class InvalidSignatureError(AptosSDKError):
    """Raised when a cryptographic signature is invalid or has an unexpected format."""


class InvalidTypeError(AptosSDKError):
    """Raised when an unexpected or unsupported type variant is encountered."""


class TransactionWorkerError(AptosSDKError):
    """Raised when the TransactionWorker encounters a state error."""


# ---------------------------------------------------------------------------
# Dual-hierarchy BCS errors
# ---------------------------------------------------------------------------

class DeserializationError(BcsError, BcsDeserializationError):
    """Raised when BCS deserialization fails.

    Inherits from both the v1 ``BcsError`` and v2 ``BcsDeserializationError``
    so it is caught by either hierarchy.
    """


class SerializationError(BcsError, BcsSerializationError):
    """Raised when BCS serialization fails due to invalid input.

    Inherits from both the v1 ``BcsError`` and v2 ``BcsSerializationError``
    so it is caught by either hierarchy.
    """


# ---------------------------------------------------------------------------
# Re-exports — allow v1 users to reach v2 errors without changing imports
# ---------------------------------------------------------------------------

__all__ = [
    # v1 originals
    "AptosSDKError",
    "BcsError",
    "DeserializationError",
    "SerializationError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidTypeError",
    "TransactionWorkerError",
    # v2 convenience aliases
    "AptosError",
    "ApiError",
    "AccountNotFoundError",
    "ResourceNotFoundError",
    "TransactionError",
    "TransactionTimeoutError",
    "TransactionFailedError",
    "V2BcsError",
    "BcsSerializationError",
    "BcsDeserializationError",
    "CryptoError",
    "V2InvalidKeyError",
    "V2InvalidSignatureError",
    "InvalidMnemonicError",
    "InvalidAddressError",
    "InvalidTypeTagError",
]
