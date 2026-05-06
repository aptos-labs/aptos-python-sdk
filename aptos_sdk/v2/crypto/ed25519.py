"""Ed25519 cryptography using PyNaCl."""

from __future__ import annotations

from nacl.signing import SigningKey, VerifyKey

from ..bcs import Deserializer, Serializer
from ..errors import InvalidKeyError, InvalidSignatureError
from .keys import PrivateKey as PrivateKeyBase
from .keys import PrivateKeyVariant, parse_hex_input
from .keys import PublicKey as PublicKeyBase
from .keys import Signature as SignatureBase


class Ed25519PrivateKey(PrivateKeyBase):
    """Ed25519 private key (32 bytes)."""

    LENGTH = 32
    __slots__ = ("_key",)

    def __init__(self, key: SigningKey) -> None:
        self._key = key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519PrivateKey):
            return NotImplemented
        return self._key.encode() == other._key.encode()

    def _variant(self) -> PrivateKeyVariant:
        return PrivateKeyVariant.ED25519

    @staticmethod
    def generate() -> Ed25519PrivateKey:
        return Ed25519PrivateKey(SigningKey.generate())

    @staticmethod
    def from_str(value: str, strict: bool | None = None) -> Ed25519PrivateKey:
        raw = parse_hex_input(value, PrivateKeyVariant.ED25519, strict)
        if len(raw) != Ed25519PrivateKey.LENGTH:
            raise InvalidKeyError(
                f"Ed25519 private key must be {Ed25519PrivateKey.LENGTH} bytes, got {len(raw)}"
            )
        return Ed25519PrivateKey(SigningKey(raw))

    @staticmethod
    def from_hex(value: str | bytes, strict: bool | None = None) -> Ed25519PrivateKey:
        raw = parse_hex_input(value, PrivateKeyVariant.ED25519, strict)
        if len(raw) != Ed25519PrivateKey.LENGTH:
            raise InvalidKeyError(
                f"Ed25519 private key must be {Ed25519PrivateKey.LENGTH} bytes, got {len(raw)}"
            )
        return Ed25519PrivateKey(SigningKey(raw))

    def hex(self) -> str:
        return f"0x{self._key.encode().hex()}"

    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey(self._key.verify_key)

    def sign(self, data: bytes) -> Ed25519Signature:
        return Ed25519Signature(self._key.sign(data).signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Ed25519PrivateKey:
        key = deserializer.to_bytes()
        if len(key) != Ed25519PrivateKey.LENGTH:
            raise InvalidKeyError("Length mismatch")
        return Ed25519PrivateKey(SigningKey(key))

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self._key.encode())


class Ed25519PublicKey(PublicKeyBase):
    """Ed25519 public key (32 bytes)."""

    LENGTH = 32
    __slots__ = ("_key",)

    def __init__(self, key: VerifyKey) -> None:
        self._key = key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519PublicKey):
            return NotImplemented
        return self._key.encode() == other._key.encode()

    def __str__(self) -> str:
        return f"0x{self._key.encode().hex()}"

    @staticmethod
    def from_str(value: str) -> Ed25519PublicKey:
        if value.startswith("0x"):
            value = value[2:]
        raw = bytes.fromhex(value)
        if len(raw) != Ed25519PublicKey.LENGTH:
            raise InvalidKeyError(
                f"Ed25519 public key must be {Ed25519PublicKey.LENGTH} bytes, got {len(raw)}"
            )
        return Ed25519PublicKey(VerifyKey(raw))

    def to_crypto_bytes(self) -> bytes:
        return self._key.encode()

    def verify(self, data: bytes, signature: SignatureBase) -> bool:
        try:
            self._key.verify(data, signature.data())
            return True
        except Exception:
            return False

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Ed25519PublicKey:
        key = deserializer.to_bytes()
        if len(key) != Ed25519PublicKey.LENGTH:
            raise InvalidKeyError("Length mismatch")
        return Ed25519PublicKey(VerifyKey(key))

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self._key.encode())


class Ed25519Signature(SignatureBase):
    """Ed25519 signature (64 bytes)."""

    LENGTH = 64
    __slots__ = ("_signature",)

    def __init__(self, signature: bytes) -> None:
        self._signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519Signature):
            return NotImplemented
        return self._signature == other._signature

    def __str__(self) -> str:
        return f"0x{self._signature.hex()}"

    def data(self) -> bytes:
        return self._signature

    @staticmethod
    def from_str(value: str) -> Ed25519Signature:
        if value.startswith("0x"):
            value = value[2:]
        return Ed25519Signature(bytes.fromhex(value))

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Ed25519Signature:
        sig = deserializer.to_bytes()
        if len(sig) != Ed25519Signature.LENGTH:
            raise InvalidSignatureError("Length mismatch")
        return Ed25519Signature(sig)

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self._signature)
