"""SingleKey wrappers — AnyPublicKey and AnySignature with variant tags for BCS."""

from __future__ import annotations

from ..bcs import Deserializer, Serializer
from ..errors import InvalidKeyError, InvalidSignatureError
from .ed25519 import Ed25519PublicKey, Ed25519Signature
from .keys import PublicKey, Signature
from .secp256k1 import Secp256k1PublicKey, Secp256k1Signature


class AnyPublicKeyVariant:
    ED25519 = 0
    SECP256K1 = 1


class AnyPublicKey(PublicKey):
    """Wraps any supported public key with a variant tag for BCS serialization."""

    __slots__ = ("_inner", "_variant")

    _inner: Ed25519PublicKey | Secp256k1PublicKey
    _variant: int

    def __init__(self, inner: PublicKey) -> None:
        if isinstance(inner, AnyPublicKey):
            self._inner = inner._inner
            self._variant = inner._variant
        elif isinstance(inner, Ed25519PublicKey):
            self._inner = inner
            self._variant = AnyPublicKeyVariant.ED25519
        elif isinstance(inner, Secp256k1PublicKey):
            self._inner = inner
            self._variant = AnyPublicKeyVariant.SECP256K1
        else:
            raise InvalidKeyError(f"Unsupported key type: {type(inner).__name__}")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AnyPublicKey):
            return NotImplemented
        return self._variant == other._variant and self._inner == other._inner

    def __str__(self) -> str:
        return str(self._inner)

    @property
    def inner(self) -> PublicKey:
        return self._inner

    def to_crypto_bytes(self) -> bytes:
        ser = Serializer()
        self.serialize(ser)
        return ser.output()

    def verify(self, data: bytes, signature: Signature) -> bool:
        if isinstance(signature, AnySignature):
            return self._inner.verify(data, signature.inner)
        return self._inner.verify(data, signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AnyPublicKey:
        variant = deserializer.uleb128()
        match variant:
            case AnyPublicKeyVariant.ED25519:
                return AnyPublicKey(Ed25519PublicKey.deserialize(deserializer))
            case AnyPublicKeyVariant.SECP256K1:
                return AnyPublicKey(Secp256k1PublicKey.deserialize(deserializer))
            case _:
                raise InvalidKeyError(f"Unknown AnyPublicKey variant: {variant}")

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self._variant)
        self._inner.serialize(serializer)


class AnySignature(Signature):
    """Wraps any supported signature with a variant tag for BCS serialization."""

    __slots__ = ("_inner", "_variant")

    _inner: Ed25519Signature | Secp256k1Signature
    _variant: int

    def __init__(self, inner: Signature) -> None:
        if isinstance(inner, AnySignature):
            self._inner = inner._inner
            self._variant = inner._variant
        elif isinstance(inner, Ed25519Signature):
            self._inner = inner
            self._variant = AnyPublicKeyVariant.ED25519
        elif isinstance(inner, Secp256k1Signature):
            self._inner = inner
            self._variant = AnyPublicKeyVariant.SECP256K1
        else:
            raise InvalidSignatureError(
                f"Unsupported signature type: {type(inner).__name__}"
            )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AnySignature):
            return NotImplemented
        return self._variant == other._variant and self._inner == other._inner

    @property
    def inner(self) -> Signature:
        return self._inner

    def data(self) -> bytes:
        return self._inner.data()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AnySignature:
        variant = deserializer.uleb128()
        match variant:
            case AnyPublicKeyVariant.ED25519:
                return AnySignature(Ed25519Signature.deserialize(deserializer))
            case AnyPublicKeyVariant.SECP256K1:
                return AnySignature(Secp256k1Signature.deserialize(deserializer))
            case _:
                raise InvalidSignatureError(f"Unknown AnySignature variant: {variant}")

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self._variant)
        self._inner.serialize(serializer)
