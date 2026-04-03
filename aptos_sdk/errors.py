# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0


class AptosSDKError(Exception):
    """Base exception for the Aptos SDK."""


class BcsError(AptosSDKError):
    """Base exception for BCS serialization/deserialization errors."""


class DeserializationError(BcsError):
    """Raised when BCS deserialization fails."""


class SerializationError(BcsError):
    """Raised when BCS serialization fails due to invalid input."""


class InvalidKeyError(AptosSDKError):
    """Raised when a cryptographic key is invalid or has an unexpected format."""


class InvalidSignatureError(AptosSDKError):
    """Raised when a cryptographic signature is invalid or has an unexpected format."""


class InvalidTypeError(AptosSDKError):
    """Raised when an unexpected or unsupported type variant is encountered."""


class TransactionWorkerError(AptosSDKError):
    """Raised when the TransactionWorker encounters a state error."""
