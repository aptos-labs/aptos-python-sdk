# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Enumeration types for the Aptos Python SDK.

This module contains IntEnum definitions for various type discriminants
used throughout the SDK for BCS serialization.
"""

from enum import IntEnum


class AuthenticatorVariant(IntEnum):
    """
    Variants for transaction authenticators.

    Used during BCS serialization to identify the type of authenticator.
    """

    ED25519 = 0
    MULTI_ED25519 = 1
    MULTI_AGENT = 2
    FEE_PAYER = 3
    SINGLE_SENDER = 4


class AccountAuthenticatorVariant(IntEnum):
    """
    Variants for account authenticators.

    Used during BCS serialization to identify the type of account authenticator.
    """

    ED25519 = 0
    MULTI_ED25519 = 1
    SINGLE_KEY = 2
    MULTI_KEY = 3


class AnyPublicKeyVariant(IntEnum):
    """
    Variants for AnyPublicKey (unified public key type).

    Supports multiple cryptographic schemes under a single type.
    """

    ED25519 = 0
    SECP256K1_ECDSA = 1
    SECP256R1_ECDSA = 2
    KEYLESS = 3


class AnySignatureVariant(IntEnum):
    """
    Variants for AnySignature (unified signature type).
    """

    ED25519 = 0
    SECP256K1_ECDSA = 1
    SECP256R1_ECDSA = 2
    KEYLESS = 3


class TypeTagVariant(IntEnum):
    """
    Variants for Move type tags.

    Used during BCS serialization to identify Move types.
    """

    BOOL = 0
    U8 = 1
    U64 = 2
    U128 = 3
    ADDRESS = 4
    SIGNER = 5
    VECTOR = 6
    STRUCT = 7
    U16 = 8
    U32 = 9
    U256 = 10


class TransactionPayloadVariant(IntEnum):
    """
    Variants for transaction payloads.
    """

    SCRIPT = 0
    # MODULE_BUNDLE = 1  # Deprecated
    ENTRY_FUNCTION = 2
    MULTISIG = 3


class TransactionArgumentVariant(IntEnum):
    """
    Variants for transaction arguments.
    """

    U8 = 0
    U64 = 1
    U128 = 2
    ADDRESS = 3
    U8_VECTOR = 4
    BOOL = 5
    U16 = 6
    U32 = 7
    U256 = 8


class PropertyType(IntEnum):
    """
    Property types for Digital Assets (NFTs).
    """

    BOOL = 0
    U8 = 1
    U16 = 2
    U32 = 3
    U64 = 4
    U128 = 5
    U256 = 6
    ADDRESS = 7
    BYTE_VECTOR = 8
    STRING = 9

