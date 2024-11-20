# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from enum import Enum

from typing_extensions import Protocol

from .bcs import Deserializable, Serializable


class PrivateKeyVariant(Enum):
    Ed25519 = "ed25519"
    Secp256k1 = "secp256k1"


class PrivateKey(Deserializable, Serializable, Protocol):
    def hex(self) -> str: ...

    def public_key(self) -> PublicKey: ...

    def sign(self, data: bytes) -> Signature: ...

    """
    The AIP-80 compliant prefixes for each private key type. Append this to a private key's hex representation
    to get an AIP-80 compliant string.

    [Read about AIP-80](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md)
    """
    AIP80_PREFIXES: dict[PrivateKeyVariant, str] = {
        PrivateKeyVariant.Ed25519: "ed25519-priv-",
        PrivateKeyVariant.Secp256k1: "secp256k1-priv-",
    }

    @staticmethod
    def format_private_key(
        private_key: bytes | str, key_type: PrivateKeyVariant
    ) -> str:
        """
        Format a HexInput to an AIP-80 compliant string.

        :param private_key: The hex string or bytes format of the private key.
        :param key_type: The private key type.
        :return: AIP-80 compliant string.
        """
        if key_type not in PrivateKey.AIP80_PREFIXES:
            raise ValueError(f"Unknown private key type: {key_type}")
        aip80_prefix = PrivateKey.AIP80_PREFIXES[key_type]

        key_value: str | None = None
        if isinstance(private_key, str):
            if private_key.startswith(aip80_prefix):
                key_value = private_key.split("-")[2]
            else:
                key_value = private_key
        elif isinstance(private_key, bytes):
            key_value = f"0x{private_key.hex()}"
        else:
            raise TypeError("Input value must be a string or bytes.")

        return f"{aip80_prefix}{key_value}"

    @staticmethod
    def parse_hex_input(
        value: str | bytes, key_type: PrivateKeyVariant, strict: bool | None = None
    ) -> bytes:
        """
        Parse a HexInput that may be a hex string, bytes, or an AIP-80 compliant string to a byte array.

        :param value: A hex string, byte array, or AIP-80 compliant string.
        :param key_type: The private key type.
        :param strict: If true, the value MUST be compliant with AIP-80.
        :return: Parsed private key as bytes.
        """
        if key_type not in PrivateKey.AIP80_PREFIXES:
            raise ValueError(f"Unknown private key type: {key_type}")
        aip80_prefix = PrivateKey.AIP80_PREFIXES[key_type]

        if isinstance(value, str):
            if not strict and not value.startswith(aip80_prefix):
                # Non-AIP-80 compliant hex string
                if strict is None:
                    print(
                        "It is recommended that private keys are AIP-80 compliant (https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md)."
                    )
                if value[0:2] == "0x":
                    value = value[2:]
                return bytes.fromhex(value)
            elif value.startswith(aip80_prefix):
                # AIP-80 compliant string
                value = value.split("-")[2]
                if value[0:2] == "0x":
                    value = value[2:]
                return bytes.fromhex(value)
            else:
                if strict:
                    raise ValueError(
                        "Invalid HexString input. Must be AIP-80 compliant string."
                    )
                raise ValueError("Invalid HexString input.")
        elif isinstance(value, bytes):
            return value
        else:
            raise TypeError("Input value must be a string or bytes.")


class PublicKey(Deserializable, Serializable, Protocol):
    def to_crypto_bytes(self) -> bytes:
        """
        A long time ago, someone decided that we should have both bcs and a special representation
        for MultiEd25519, so we use this to let keys self-define a special encoding.
        """
        ...

    def verify(self, data: bytes, signature: Signature) -> bool: ...


class Signature(Deserializable, Serializable, Protocol): ...
