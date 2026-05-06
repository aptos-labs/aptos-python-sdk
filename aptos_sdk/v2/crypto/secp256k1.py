"""Secp256k1 ECDSA cryptography using the cryptography library (OpenSSL)."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

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

    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        self._key = key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secp256k1PrivateKey):
            return NotImplemented
        return (
            self._key.private_numbers().private_value == other._key.private_numbers().private_value
        )

    def _variant(self) -> PrivateKeyVariant:
        return PrivateKeyVariant.SECP256K1

    @staticmethod
    def generate() -> Secp256k1PrivateKey:
        return Secp256k1PrivateKey(ec.generate_private_key(ec.SECP256K1()))

    @staticmethod
    def _from_raw(raw: bytes) -> Secp256k1PrivateKey:
        if len(raw) != Secp256k1PrivateKey.LENGTH:
            raise InvalidKeyError("Length mismatch")
        private_int = int.from_bytes(raw, "big")
        if not (1 <= private_int < _N):
            raise InvalidKeyError("Secp256k1 private key scalar must be in [1, N)")
        return Secp256k1PrivateKey(ec.derive_private_key(private_int, ec.SECP256K1()))

    @staticmethod
    def from_str(value: str, strict: bool | None = None) -> Secp256k1PrivateKey:
        raw = parse_hex_input(value, PrivateKeyVariant.SECP256K1, strict)
        return Secp256k1PrivateKey._from_raw(raw)

    @staticmethod
    def from_hex(value: str | bytes, strict: bool | None = None) -> Secp256k1PrivateKey:
        raw = parse_hex_input(value, PrivateKeyVariant.SECP256K1, strict)
        return Secp256k1PrivateKey._from_raw(raw)

    def hex(self) -> str:
        raw = self._key.private_numbers().private_value.to_bytes(self.LENGTH, "big")
        return f"0x{raw.hex()}"

    def public_key(self) -> Secp256k1PublicKey:
        pub = self._key.public_key()
        nums = pub.public_numbers()
        raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
        return Secp256k1PublicKey(raw)

    def sign(self, data: bytes) -> Secp256k1Signature:
        der_sig = self._key.sign(data, ec.ECDSA(hashes.SHA3_256()))
        r, s = decode_dss_signature(der_sig)
        # Low-S normalization: if s > n/2, use n - s
        if s > _N // 2:
            s = _N - s
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return Secp256k1Signature(sig_bytes)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Secp256k1PrivateKey:
        key = deserializer.to_bytes()
        return Secp256k1PrivateKey._from_raw(key)

    def serialize(self, serializer: Serializer) -> None:
        raw = self._key.private_numbers().private_value.to_bytes(self.LENGTH, "big")
        serializer.to_bytes(raw)


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
            if len(sig_bytes) != 64:
                return False
            r = int.from_bytes(sig_bytes[0:32], "big")
            s = int.from_bytes(sig_bytes[32:64], "big")
            if r == 0 or s == 0:
                return False
            if s > (_N // 2):
                return False
            der_sig = encode_dss_signature(r, s)
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x04" + self._raw)
            pub.verify(der_sig, data, ec.ECDSA(hashes.SHA3_256()))
        except Exception:
            return False
        return True

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
