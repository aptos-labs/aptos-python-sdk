"""Secp256k1 ECDSA cryptography using coincurve (wraps libsecp256k1)."""

from __future__ import annotations

import hashlib

from coincurve import PrivateKey as CoinPrivateKey
from coincurve import PublicKey as CoinPublicKey

from ..bcs import Deserializer, Serializer
from ..errors import InvalidKeyError, InvalidSignatureError
from .keys import PrivateKey as PrivateKeyBase
from .keys import PrivateKeyVariant, parse_hex_input
from .keys import PublicKey as PublicKeyBase
from .keys import Signature as SignatureBase

# secp256k1 curve order
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class Secp256k1PrivateKey(PrivateKeyBase):
    """Secp256k1 ECDSA private key (32 bytes)."""

    LENGTH = 32
    __slots__ = ("_key",)

    def __init__(self, key: CoinPrivateKey) -> None:
        self._key = key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secp256k1PrivateKey):
            return NotImplemented
        return self._key.secret == other._key.secret

    def _variant(self) -> PrivateKeyVariant:
        return PrivateKeyVariant.SECP256K1

    @staticmethod
    def generate() -> Secp256k1PrivateKey:
        return Secp256k1PrivateKey(CoinPrivateKey())

    @staticmethod
    def from_str(value: str, strict: bool | None = None) -> Secp256k1PrivateKey:
        raw = parse_hex_input(value, PrivateKeyVariant.SECP256K1, strict)
        if len(raw) != Secp256k1PrivateKey.LENGTH:
            raise InvalidKeyError("Length mismatch")
        return Secp256k1PrivateKey(CoinPrivateKey(raw))

    @staticmethod
    def from_hex(value: str | bytes, strict: bool | None = None) -> Secp256k1PrivateKey:
        raw = parse_hex_input(value, PrivateKeyVariant.SECP256K1, strict)
        if len(raw) != Secp256k1PrivateKey.LENGTH:
            raise InvalidKeyError("Length mismatch")
        return Secp256k1PrivateKey(CoinPrivateKey(raw))

    def hex(self) -> str:
        return f"0x{self._key.secret.hex()}"

    def public_key(self) -> Secp256k1PublicKey:
        # uncompressed format: 04 || x (32 bytes) || y (32 bytes), skip the 04 prefix
        raw_uncompressed = self._key.public_key.format(compressed=False)
        return Secp256k1PublicKey(raw_uncompressed[1:])

    def sign(self, data: bytes) -> Secp256k1Signature:
        digest = hashlib.sha3_256(data).digest()
        # coincurve sign_recoverable returns (r || s || recovery_id)
        # We use ecdsa_sign which returns DER, so we use sign_recoverable and strip recovery
        sig_raw = self._key.sign_recoverable(digest, hasher=None)
        r = int.from_bytes(sig_raw[0:32], "big")
        s = int.from_bytes(sig_raw[32:64], "big")
        # Low-S normalization: if s > n/2, use n - s
        # Note: libsecp256k1 already normalizes S in sign_recoverable, so this
        # branch is a safety net that won't trigger in practice.
        if s > _N // 2:  # pragma: no cover
            s = _N - s
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return Secp256k1Signature(sig_bytes)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Secp256k1PrivateKey:
        key = deserializer.to_bytes()
        if len(key) != Secp256k1PrivateKey.LENGTH:
            raise InvalidKeyError("Length mismatch")
        return Secp256k1PrivateKey(CoinPrivateKey(key))

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self._key.secret)


class Secp256k1PublicKey(PublicKeyBase):
    """Secp256k1 public key (64 bytes raw, serialized with 0x04 prefix as 65 bytes)."""

    LENGTH = 64
    __slots__ = ("_raw",)

    def __init__(self, raw: bytes) -> None:
        if len(raw) == 65 and raw[0] == 0x04:
            raw = raw[1:]
        if len(raw) != self.LENGTH:
            raise InvalidKeyError(
                f"Secp256k1 public key must be {self.LENGTH} bytes, got {len(raw)}"
            )
        self._raw = raw

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secp256k1PublicKey):
            return NotImplemented
        return self._raw == other._raw

    def __str__(self) -> str:
        return f"0x04{self._raw.hex()}"

    @staticmethod
    def from_str(value: str) -> Secp256k1PublicKey:
        if value.startswith("0x"):
            value = value[2:]
        raw = bytes.fromhex(value)
        if len(raw) == 65 and raw[0] == 0x04:
            raw = raw[1:]
        return Secp256k1PublicKey(raw)

    def to_crypto_bytes(self) -> bytes:
        return b"\x04" + self._raw

    def verify(self, data: bytes, signature: SignatureBase) -> bool:
        try:
            sig_bytes = signature.data()
            r = int.from_bytes(sig_bytes[0:32], "big")
            s = int.from_bytes(sig_bytes[32:64], "big")
            # Build DER encoding for coincurve
            der_sig = _rs_to_der(r, s)
            digest = hashlib.sha3_256(data).digest()
            pub = CoinPublicKey(b"\x04" + self._raw)
            return pub.verify(der_sig, digest, hasher=None)
        except Exception:
            return False

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Secp256k1PublicKey:
        key = deserializer.to_bytes()
        return Secp256k1PublicKey(key)

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self.to_crypto_bytes())


class Secp256k1Signature(SignatureBase):
    """Secp256k1 ECDSA signature (64 bytes: r || s)."""

    LENGTH = 64
    __slots__ = ("_signature",)

    def __init__(self, signature: bytes) -> None:
        self._signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secp256k1Signature):
            return NotImplemented
        return self._signature == other._signature

    def __str__(self) -> str:
        return f"0x{self._signature.hex()}"

    def data(self) -> bytes:
        return self._signature

    @staticmethod
    def from_str(value: str) -> Secp256k1Signature:
        if value.startswith("0x"):
            value = value[2:]
        if len(value) != Secp256k1Signature.LENGTH * 2:
            raise InvalidSignatureError("Length mismatch")
        return Secp256k1Signature(bytes.fromhex(value))

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Secp256k1Signature:
        sig = deserializer.to_bytes()
        if len(sig) != Secp256k1Signature.LENGTH:
            raise InvalidSignatureError("Length mismatch")
        return Secp256k1Signature(sig)

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self._signature)


def _rs_to_der(r: int, s: int) -> bytes:
    """Encode r, s integers as a DER-encoded ECDSA signature."""

    def _int_to_der_bytes(val: int) -> bytes:
        b = val.to_bytes((val.bit_length() + 8) // 8, "big")
        return b

    r_bytes = _int_to_der_bytes(r)
    s_bytes = _int_to_der_bytes(s)

    r_len = len(r_bytes)
    s_len = len(s_bytes)
    total_len = 2 + r_len + 2 + s_len

    return bytes([0x30, total_len, 0x02, r_len]) + r_bytes + bytes([0x02, s_len]) + s_bytes
