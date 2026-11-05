"""SLH-DSA-SHA2-128s (FIPS 205 / SPHINCS+) cryptography.

Implements the post-quantum scheme added by AIP-137, matching
``aptos-labs/aptos-ts-sdk`` PR #802:

* public key: 32 bytes (``PK.seed || PK.root``)
* private key: the 48-byte "three seeds" value (``SK.seed || SK.prf || PK.seed``);
  the 64-byte FIPS 205 secret key is ``three_seeds || PK.root``
* signature: 7,856 bytes
* ``AnyPublicKey`` variant 5 and ``AnySignature`` variant 4

Signing and verification are delegated to the optional ``pqcrypto``
dependency (PQClean-backed C bindings, abi3 wheels). Install it with
``pip install "aptos-sdk-v2[slh-dsa-sha2-128s]"``. Key handling, BCS
(de)serialization, address derivation, and deriving the public key from
the 48-byte seed value only use the standard library, so this module can
be imported (and on-chain data decoded) without ``pqcrypto`` installed.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

from ..bcs import Deserializer, Serializer
from ..errors import InvalidKeyError, InvalidSignatureError
from .keys import PrivateKey as PrivateKeyBase
from .keys import PrivateKeyVariant, parse_hex_input
from .keys import PublicKey as PublicKeyBase
from .keys import Signature as SignatureBase

# FIPS 205 parameters for SLH-DSA-SHA2-128s.
_N = 16  # security parameter (bytes)
_WOTS_LEN = 35  # len1 (32) + len2 (3) for w = 16
_XMSS_HEIGHT = 9  # h / d = 63 / 7
_TOP_LAYER = 6  # d - 1
_HARDENED_OFFSET = 0x80000000

# ADRS types (FIPS 205 section 4.2).
_ADRS_WOTS_HASH = 0
_ADRS_WOTS_PK = 1
_ADRS_TREE = 2
_ADRS_WOTS_PRF = 5


def _load_pqcrypto() -> Any:
    """Import the optional SLH-DSA backend, with an actionable error if absent."""
    try:
        from pqcrypto.sign import slh_dsa_sha2_128s
    except ImportError as exc:
        raise ImportError(
            "SLH-DSA-SHA2-128s signing/verification requires the optional "
            "'pqcrypto' dependency. Install it with: "
            'pip install "aptos-sdk-v2[slh-dsa-sha2-128s]"'
        ) from exc
    return slh_dsa_sha2_128s


def _adrs(layer: int, tree: int, type_: int, word3: int, word4: int, word5: int) -> bytes:
    return (
        layer.to_bytes(4, "big")
        + tree.to_bytes(12, "big")
        + type_.to_bytes(4, "big")
        + word3.to_bytes(4, "big")
        + word4.to_bytes(4, "big")
        + word5.to_bytes(4, "big")
    )


def _compressed_adrs(adrs: bytes) -> bytes:
    # ADRS^c for the SHA2 instantiations (FIPS 205 section 11.2).
    return adrs[3:4] + adrs[8:16] + adrs[19:32]


def _sha2_hash(pk_seed: bytes, adrs: bytes, message: bytes) -> bytes:
    """The F / PRF / H / T_l functions, all SHA-256 truncated to n bytes here."""
    digest = hashlib.sha256(pk_seed + b"\x00" * (64 - _N) + _compressed_adrs(adrs) + message)
    return digest.digest()[:_N]


def _wots_public_key(sk_seed: bytes, pk_seed: bytes, keypair: int) -> bytes:
    chains = bytearray()
    for chain in range(_WOTS_LEN):
        secret = _sha2_hash(
            pk_seed, _adrs(_TOP_LAYER, 0, _ADRS_WOTS_PRF, keypair, chain, 0), sk_seed
        )
        value = secret
        for step in range(15):
            value = _sha2_hash(
                pk_seed, _adrs(_TOP_LAYER, 0, _ADRS_WOTS_HASH, keypair, chain, step), value
            )
        chains.extend(value)
    return _sha2_hash(pk_seed, _adrs(_TOP_LAYER, 0, _ADRS_WOTS_PK, keypair, 0, 0), bytes(chains))


def _xmss_node(sk_seed: bytes, pk_seed: bytes, index: int, height: int) -> bytes:
    if height == 0:
        return _wots_public_key(sk_seed, pk_seed, index)
    left = _xmss_node(sk_seed, pk_seed, 2 * index, height - 1)
    right = _xmss_node(sk_seed, pk_seed, 2 * index + 1, height - 1)
    return _sha2_hash(pk_seed, _adrs(_TOP_LAYER, 0, _ADRS_TREE, 0, height, index), left + right)


def _derive_public_key_bytes(three_seeds: bytes) -> bytes:
    """Derive ``PK.seed || PK.root`` (32 bytes) from the 48-byte three-seeds value."""
    sk_seed, pk_seed = three_seeds[:_N], three_seeds[2 * _N : 3 * _N]
    return pk_seed + _xmss_node(sk_seed, pk_seed, 0, _XMSS_HEIGHT)


def _hmac_sha512(key: bytes, data: bytes) -> tuple[bytes, bytes]:
    digest = hmac.new(key, data, hashlib.sha512).digest()
    return digest[:32], digest[32:]


class SlhDsaSha2128sPrivateKey(PrivateKeyBase):
    """SLH-DSA-SHA2-128s private key (48-byte three-seeds representation)."""

    LENGTH = 48
    SLIP_0010_SEED = "SLH-DSA-SHA2-128s seed"
    __slots__ = ("_public_key_bytes", "_secret_key", "_three_seeds")

    def __init__(self, three_seeds: bytes) -> None:
        if len(three_seeds) != SlhDsaSha2128sPrivateKey.LENGTH:
            raise InvalidKeyError(
                f"SLH-DSA-SHA2-128s private key must be "
                f"{SlhDsaSha2128sPrivateKey.LENGTH} bytes, got {len(three_seeds)}"
            )
        self._three_seeds = bytes(three_seeds)
        self._secret_key: bytes | None = None
        self._public_key_bytes: bytes | None = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SlhDsaSha2128sPrivateKey):
            return NotImplemented
        return self._three_seeds == other._three_seeds

    def _variant(self) -> PrivateKeyVariant:
        return PrivateKeyVariant.SLH_DSA_SHA2_128S

    def _derive_keys(self) -> tuple[bytes, bytes]:
        """Return (64-byte FIPS 205 secret key, 32-byte public key), cached."""
        if self._secret_key is None or self._public_key_bytes is None:
            public_key = _derive_public_key_bytes(self._three_seeds)
            self._public_key_bytes = public_key
            self._secret_key = self._three_seeds + public_key[_N:]
        return self._secret_key, self._public_key_bytes

    @classmethod
    def generate(cls) -> SlhDsaSha2128sPrivateKey:
        return cls(secrets.token_bytes(cls.LENGTH))

    @classmethod
    def from_str(cls, value: str, strict: bool | None = None) -> SlhDsaSha2128sPrivateKey:
        raw = parse_hex_input(value, PrivateKeyVariant.SLH_DSA_SHA2_128S, strict)
        return cls(raw)

    @classmethod
    def from_hex(cls, value: str | bytes, strict: bool | None = None) -> SlhDsaSha2128sPrivateKey:
        raw = parse_hex_input(value, PrivateKeyVariant.SLH_DSA_SHA2_128S, strict)
        return cls(raw)

    @classmethod
    def from_derivation_path_inner(cls, path: str, seed: bytes) -> SlhDsaSha2128sPrivateKey:
        """Derive from a hardened SLIP-0010-style path and a raw seed.

        Mirrors the TS SDK: the master key is
        ``HMAC-SHA512("SLH-DSA-SHA2-128s seed", seed)`` and the 48-byte
        private key is the final derived key (32 bytes) followed by the
        first 16 bytes of the final chain code.
        """
        key, chain_code = _hmac_sha512(cls.SLIP_0010_SEED.encode(), seed)
        if path != "m":
            parts = path.split("/")
            if len(parts) < 2 or parts[0] != "m":
                raise InvalidKeyError(f"Invalid derivation path {path}")
            for segment in parts[1:]:
                if not segment.endswith("'"):
                    raise InvalidKeyError(
                        f"Invalid derivation path {path}: "
                        "SLH-DSA-SHA2-128s supports hardened derivation only"
                    )
                try:
                    index = int(segment[:-1])
                except ValueError as exc:
                    raise InvalidKeyError(f"Invalid derivation path {path}") from exc
                key, chain_code = _hmac_sha512(
                    chain_code, b"\x00" + key + (index + _HARDENED_OFFSET).to_bytes(4, "big")
                )
        return cls(key + chain_code[:_N])

    @classmethod
    def from_derivation_path(cls, path: str, mnemonic: str) -> SlhDsaSha2128sPrivateKey:
        """Derive from a BIP-39 mnemonic phrase and a hardened derivation path."""
        normalized = " ".join(mnemonic.strip().lower().split())
        seed = hashlib.pbkdf2_hmac("sha512", normalized.encode(), b"mnemonic", 2048, dklen=64)
        return cls.from_derivation_path_inner(path, seed)

    def hex(self) -> str:
        return f"0x{self._three_seeds.hex()}"

    def public_key(self) -> SlhDsaSha2128sPublicKey:
        _, public_key = self._derive_keys()
        return SlhDsaSha2128sPublicKey(public_key)

    def sign(self, data: bytes) -> SlhDsaSha2128sSignature:
        secret_key, _ = self._derive_keys()
        signature = _load_pqcrypto().sign(secret_key, data)
        return SlhDsaSha2128sSignature(bytes(signature))

    @classmethod
    def deserialize(cls, deserializer: Deserializer) -> SlhDsaSha2128sPrivateKey:
        return cls(deserializer.to_bytes())

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self._three_seeds)


class SlhDsaSha2128sPublicKey(PublicKeyBase):
    """SLH-DSA-SHA2-128s public key (32 bytes)."""

    LENGTH = 32
    __slots__ = ("_raw",)

    def __init__(self, raw: bytes) -> None:
        if len(raw) != SlhDsaSha2128sPublicKey.LENGTH:
            raise InvalidKeyError(
                f"SLH-DSA-SHA2-128s public key must be "
                f"{SlhDsaSha2128sPublicKey.LENGTH} bytes, got {len(raw)}"
            )
        self._raw = bytes(raw)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SlhDsaSha2128sPublicKey):
            return NotImplemented
        return self._raw == other._raw

    def __str__(self) -> str:
        return f"0x{self._raw.hex()}"

    @classmethod
    def from_str(cls, value: str) -> SlhDsaSha2128sPublicKey:
        if value.startswith("0x"):
            value = value[2:]
        return cls(bytes.fromhex(value))

    def to_crypto_bytes(self) -> bytes:
        return self._raw

    def verify(self, data: bytes, signature: SignatureBase) -> bool:
        backend = _load_pqcrypto()
        try:
            backend.verify(self._raw, data, signature.data())
        except Exception:
            return False
        return True

    @classmethod
    def deserialize(cls, deserializer: Deserializer) -> SlhDsaSha2128sPublicKey:
        return cls(deserializer.to_bytes())

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self._raw)


class SlhDsaSha2128sSignature(SignatureBase):
    """SLH-DSA-SHA2-128s signature (7,856 bytes)."""

    LENGTH = 7856
    __slots__ = ("_signature",)

    def __init__(self, signature: bytes) -> None:
        if len(signature) != SlhDsaSha2128sSignature.LENGTH:
            raise InvalidSignatureError(
                f"SLH-DSA-SHA2-128s signature must be "
                f"{SlhDsaSha2128sSignature.LENGTH} bytes, got {len(signature)}"
            )
        self._signature = bytes(signature)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SlhDsaSha2128sSignature):
            return NotImplemented
        return self._signature == other._signature

    def __str__(self) -> str:
        return f"0x{self._signature.hex()}"

    def data(self) -> bytes:
        return self._signature

    @classmethod
    def from_str(cls, value: str) -> SlhDsaSha2128sSignature:
        if value.startswith("0x"):
            value = value[2:]
        return cls(bytes.fromhex(value))

    @classmethod
    def deserialize(cls, deserializer: Deserializer) -> SlhDsaSha2128sSignature:
        return cls(deserializer.to_bytes())

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self._signature)
