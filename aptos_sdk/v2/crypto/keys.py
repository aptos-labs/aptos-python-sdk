"""Abstract base classes for cryptographic keys and signatures."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from ..bcs import Deserializer, Serializer


class PrivateKeyVariant(Enum):
    ED25519 = "ed25519"
    SECP256K1 = "secp256k1"


AIP80_PREFIXES: dict[PrivateKeyVariant, str] = {
    PrivateKeyVariant.ED25519: "ed25519-priv-",
    PrivateKeyVariant.SECP256K1: "secp256k1-priv-",
}


class PrivateKey(ABC):
    """Abstract base class for private keys."""

    @abstractmethod
    def hex(self) -> str: ...

    @abstractmethod
    def public_key(self) -> PublicKey: ...

    @abstractmethod
    def sign(self, data: bytes) -> Signature: ...

    @abstractmethod
    def serialize(self, serializer: Serializer) -> None: ...

    @staticmethod
    @abstractmethod
    def deserialize(deserializer: Deserializer) -> PrivateKey: ...

    def aip80(self) -> str:
        return format_private_key(self.hex(), self._variant())

    def __str__(self) -> str:
        return self.aip80()

    @abstractmethod
    def _variant(self) -> PrivateKeyVariant: ...


class PublicKey(ABC):
    """Abstract base class for public keys."""

    @abstractmethod
    def to_crypto_bytes(self) -> bytes: ...

    @abstractmethod
    def verify(self, data: bytes, signature: Signature) -> bool: ...

    @abstractmethod
    def serialize(self, serializer: Serializer) -> None: ...

    @staticmethod
    @abstractmethod
    def deserialize(deserializer: Deserializer) -> PublicKey: ...


class Signature(ABC):
    """Abstract base class for signatures."""

    @abstractmethod
    def data(self) -> bytes: ...

    @abstractmethod
    def serialize(self, serializer: Serializer) -> None: ...

    @staticmethod
    @abstractmethod
    def deserialize(deserializer: Deserializer) -> Signature: ...


# --- AIP-80 helpers ---


def format_private_key(key_hex: str, variant: PrivateKeyVariant) -> str:
    prefix = AIP80_PREFIXES[variant]
    if key_hex.startswith(prefix):
        return key_hex
    return f"{prefix}{key_hex}"


def parse_hex_input(
    value: str | bytes,
    variant: PrivateKeyVariant,
    strict: bool | None = None,
) -> bytes:
    """Parse a hex string, bytes, or AIP-80 compliant string to raw key bytes."""
    prefix = AIP80_PREFIXES[variant]

    if isinstance(value, bytes):
        return value

    if isinstance(value, str):
        if value.startswith(prefix):
            hex_part = value.split("-")[2]
            if hex_part.startswith("0x"):
                hex_part = hex_part[2:]
            return bytes.fromhex(hex_part)
        elif strict:
            raise ValueError("Invalid HexString input. Must be AIP-80 compliant string.")
        else:
            if value.startswith("0x"):
                value = value[2:]
            return bytes.fromhex(value)

    raise TypeError("Input value must be a string or bytes.")
