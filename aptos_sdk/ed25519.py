# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from typing import List, Tuple, cast

from nacl.signing import SigningKey, VerifyKey

from . import asymmetric_crypto
from .bcs import Deserializer, Serializer
from .errors import InvalidKeyError, InvalidSignatureError

# ---------------------------------------------------------------------------
# Bootstrap v2 crypto modules without triggering the heavy v2/__init__.py
# or v2/crypto/__init__.py.  The v2 package stub and v2.bcs/v2.errors are
# already registered by aptos_sdk.bcs (imported above).
# ---------------------------------------------------------------------------

_v2_dir = os.path.join(os.path.dirname(__file__), "v2")
_crypto_dir = os.path.join(_v2_dir, "crypto")


def _load_module(fqn: str, filepath: str) -> types.ModuleType:
    """Load a single .py file as *fqn* without running any package __init__."""
    if fqn in sys.modules:
        return sys.modules[fqn]
    spec = importlib.util.spec_from_file_location(fqn, filepath)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[fqn] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# Ensure the v2.crypto namespace package stub exists.
if "aptos_sdk.v2.crypto" not in sys.modules:
    _crypto_pkg = types.ModuleType("aptos_sdk.v2.crypto")
    _crypto_pkg.__path__ = [_crypto_dir]  # type: ignore[attr-defined]
    _crypto_pkg.__package__ = "aptos_sdk.v2.crypto"
    sys.modules["aptos_sdk.v2.crypto"] = _crypto_pkg

_load_module("aptos_sdk.v2.crypto.keys", os.path.join(_crypto_dir, "keys.py"))
_ed25519_mod = _load_module(
    "aptos_sdk.v2.crypto.ed25519", os.path.join(_crypto_dir, "ed25519.py")
)

_V2PrivateKey = _ed25519_mod.Ed25519PrivateKey
_V2PublicKey = _ed25519_mod.Ed25519PublicKey
_V2Signature = _ed25519_mod.Ed25519Signature


class PrivateKey(asymmetric_crypto.PrivateKey):
    LENGTH: int = 32

    _inner: _V2PrivateKey

    def __init__(self, key: SigningKey):
        self._inner = _V2PrivateKey(key)

    @property
    def key(self) -> SigningKey:
        return self._inner._key

    def __eq__(self, other: object):
        if not isinstance(other, PrivateKey):
            return NotImplemented
        return self._inner == other._inner

    def __str__(self):
        return self.aip80()

    @staticmethod
    def from_hex(value: str | bytes, strict: bool | None = None) -> PrivateKey:
        """
        Parse a HexInput that may be a hex string, bytes, or an AIP-80 compliant string to a private key.

        :param value: A hex string, byte array, or AIP-80 compliant string.
        :param strict: If true, the value MUST be compliant with AIP-80.
        :return: Parsed Ed25519 private key.
        """
        v2 = _V2PrivateKey.from_hex(value, strict)
        pk = PrivateKey.__new__(PrivateKey)
        pk._inner = v2
        return pk

    @staticmethod
    def from_str(value: str, strict: bool | None = None) -> PrivateKey:
        """
        Parse a HexInput that may be a hex string or an AIP-80 compliant string to a private key.

        :param value: A hex string or AIP-80 compliant string.
        :param strict: If true, the value MUST be compliant with AIP-80.
        :return: Parsed Ed25519 private key.
        """
        return PrivateKey.from_hex(value, strict)

    def hex(self) -> str:
        return self._inner.hex()

    def aip80(self) -> str:
        return PrivateKey.format_private_key(
            self.hex(), asymmetric_crypto.PrivateKeyVariant.Ed25519
        )

    def public_key(self) -> PublicKey:
        v2_pub = self._inner.public_key()
        pub = PublicKey.__new__(PublicKey)
        pub._inner = v2_pub
        return pub

    @staticmethod
    def random() -> PrivateKey:
        v2 = _V2PrivateKey.generate()
        pk = PrivateKey.__new__(PrivateKey)
        pk._inner = v2
        return pk

    def sign(self, data: bytes) -> Signature:
        v2_sig = self._inner.sign(data)
        sig = Signature.__new__(Signature)
        sig._inner = v2_sig
        return sig

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PrivateKey:
        v2 = _V2PrivateKey.deserialize(deserializer)
        pk = PrivateKey.__new__(PrivateKey)
        pk._inner = v2
        return pk

    def serialize(self, serializer: Serializer):
        self._inner.serialize(serializer)


class PublicKey(asymmetric_crypto.PublicKey):
    LENGTH: int = 32

    _inner: _V2PublicKey

    def __init__(self, key: VerifyKey):
        self._inner = _V2PublicKey(key)

    @property
    def key(self) -> VerifyKey:
        return self._inner._key

    def __eq__(self, other: object):
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self._inner == other._inner

    def __str__(self) -> str:
        return str(self._inner)

    @staticmethod
    def from_str(value: str) -> PublicKey:
        v2_pub = _V2PublicKey.from_str(value)
        pub = PublicKey.__new__(PublicKey)
        pub._inner = v2_pub
        return pub

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            signature = cast(Signature, signature)
            self._inner._key.verify(data, signature.data())
        except Exception:
            return False
        return True

    def to_crypto_bytes(self) -> bytes:
        return self._inner.to_crypto_bytes()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PublicKey:
        v2_pub = _V2PublicKey.deserialize(deserializer)
        pub = PublicKey.__new__(PublicKey)
        pub._inner = v2_pub
        return pub

    def serialize(self, serializer: Serializer):
        self._inner.serialize(serializer)


class MultiPublicKey(asymmetric_crypto.PublicKey):
    keys: List[PublicKey]
    threshold: int

    MIN_KEYS = 2
    MAX_KEYS = 32
    MIN_THRESHOLD = 1

    def __init__(self, keys: List[PublicKey], threshold: int):
        if not (self.MIN_KEYS <= len(keys) <= self.MAX_KEYS):
            raise ValueError(
                f"Must have between {self.MIN_KEYS} and {self.MAX_KEYS} keys."
            )
        if not (self.MIN_THRESHOLD <= threshold <= len(keys)):
            raise ValueError(
                f"Threshold must be between {self.MIN_THRESHOLD} and {len(keys)}."
            )

        self.keys = keys
        self.threshold = threshold

    def __str__(self) -> str:
        return f"{self.threshold}-of-{len(self.keys)} Multi-Ed25519 public key"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            signatures = cast(MultiSignature, signature)
            if self.threshold > len(signatures.signatures):
                return False

            for idx, signature in signatures.signatures:
                if len(self.keys) <= idx:
                    return False
                if not self.keys[idx].verify(data, signature):
                    return False
        except Exception:
            return False
        return True

    @staticmethod
    def from_crypto_bytes(indata: bytes) -> MultiPublicKey:
        total_keys = int(len(indata) / PublicKey.LENGTH)
        keys: List[PublicKey] = []
        for idx in range(total_keys):
            start = idx * PublicKey.LENGTH
            end = (idx + 1) * PublicKey.LENGTH
            keys.append(PublicKey(VerifyKey(indata[start:end])))
        threshold = indata[-1]
        return MultiPublicKey(keys, threshold)

    def to_crypto_bytes(self) -> bytes:
        key_bytes = bytearray()
        for key in self.keys:
            key_bytes.extend(key.to_crypto_bytes())
        key_bytes.append(self.threshold)
        return key_bytes

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiPublicKey:
        indata = deserializer.to_bytes()
        return MultiPublicKey.from_crypto_bytes(indata)

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self.to_crypto_bytes())


class Signature(asymmetric_crypto.Signature):
    LENGTH: int = 64

    _inner: _V2Signature

    def __init__(self, signature: bytes):
        self._inner = _V2Signature(signature)

    @property
    def signature(self) -> bytes:
        return self._inner._signature

    def __eq__(self, other: object):
        if not isinstance(other, Signature):
            return NotImplemented
        return self._inner == other._inner

    def __str__(self) -> str:
        return str(self._inner)

    def data(self) -> bytes:
        return self._inner.data()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Signature:
        v2_sig = _V2Signature.deserialize(deserializer)
        sig = Signature.__new__(Signature)
        sig._inner = v2_sig
        return sig

    @staticmethod
    def from_str(value: str) -> Signature:
        v2_sig = _V2Signature.from_str(value)
        sig = Signature.__new__(Signature)
        sig._inner = v2_sig
        return sig

    def serialize(self, serializer: Serializer):
        self._inner.serialize(serializer)


class MultiSignature(asymmetric_crypto.Signature):
    signatures: List[Tuple[int, Signature]]
    BITMAP_NUM_OF_BYTES: int = 4

    def __init__(self, signatures: List[Tuple[int, Signature]]):
        for signature in signatures:
            if signature[0] >= self.BITMAP_NUM_OF_BYTES * 8:
                raise ValueError("bitmap value exceeds maximum value")
        self.signatures = signatures

    def __eq__(self, other: object):
        if not isinstance(other, MultiSignature):
            return NotImplemented
        return self.signatures == other.signatures

    def __str__(self) -> str:
        return f"{self.signatures}"

    @staticmethod
    def from_key_map(
        public_key: MultiPublicKey,
        signatures_map: List[Tuple[PublicKey, Signature]],
    ) -> MultiSignature:
        signatures = []

        for entry in signatures_map:
            signatures.append((public_key.keys.index(entry[0]), entry[1]))
        return MultiSignature(signatures)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiSignature:
        signature_bytes = deserializer.to_bytes()
        count = len(signature_bytes) // Signature.LENGTH
        if count * Signature.LENGTH + MultiSignature.BITMAP_NUM_OF_BYTES != len(
            signature_bytes
        ):
            raise ValueError("MultiSignature length is invalid")

        bitmap = int.from_bytes(signature_bytes[-4:], "big")

        current = 0
        position = 0
        signatures = []
        while current < count:
            to_check = 1 << (31 - position)
            if to_check & bitmap:
                left = current * Signature.LENGTH
                signature = Signature(signature_bytes[left : left + Signature.LENGTH])
                signatures.append((position, signature))
                current += 1
            position += 1

        return MultiSignature(signatures)

    def serialize(self, serializer: Serializer):
        signature_bytes = bytearray()
        bitmap = 0

        for signature in self.signatures:
            shift = 31 - signature[0]
            bitmap = bitmap | (1 << shift)
            signature_bytes.extend(signature[1].data())

        signature_bytes.extend(
            bitmap.to_bytes(MultiSignature.BITMAP_NUM_OF_BYTES, "big")
        )
        serializer.to_bytes(signature_bytes)


class Test(unittest.TestCase):
    def test_private_key_from_str(self):
        private_key_hex = PrivateKey.from_str(
            "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe", False
        )
        private_key_with_prefix = PrivateKey.from_str(
            "ed25519-priv-0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe",
            True,
        )
        private_key_bytes = PrivateKey.from_hex(
            bytes.fromhex(
                "4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
            ),
            False,
        )
        self.assertEqual(
            private_key_hex.hex(),
            private_key_with_prefix.hex(),
            private_key_bytes.hex(),
        )

    def test_private_key_aip80_formatting(self):
        private_key_with_prefix = "ed25519-priv-0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        self.assertEqual(
            str(PrivateKey.from_str(private_key_with_prefix, True)),
            private_key_with_prefix,
        )

    def test_sign_and_verify(self):
        in_value = b"test_message"

        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        signature = private_key.sign(in_value)
        self.assertTrue(public_key.verify(in_value, signature))

    def test_private_key_serialization(self):
        private_key = PrivateKey.random()
        ser = Serializer()

        private_key.serialize(ser)
        ser_private_key = PrivateKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(private_key, ser_private_key)

    def test_public_key_serialization(self):
        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        ser = Serializer()
        public_key.serialize(ser)
        ser_public_key = PublicKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(public_key, ser_public_key)

    def test_signature_key_serialization(self):
        private_key = PrivateKey.random()
        in_value = b"another_message"
        signature = private_key.sign(in_value)

        ser = Serializer()
        signature.serialize(ser)
        ser_signature = Signature.deserialize(Deserializer(ser.output()))
        self.assertEqual(signature, ser_signature)

    def test_multisig(self):
        # Generate signatory private keys.
        private_key_1 = PrivateKey.from_str(
            "ed25519-priv-0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        private_key_2 = PrivateKey.from_str(
            "ed25519-priv-0x1e70e49b78f976644e2c51754a2f049d3ff041869c669523ba95b172c7329901"
        )
        # Generate multisig public key with threshold of 1.
        multisig_public_key = MultiPublicKey(
            [private_key_1.public_key(), private_key_2.public_key()], 1
        )
        # Get public key BCS representation.
        serializer = Serializer()
        multisig_public_key.serialize(serializer)
        public_key_bcs = serializer.output().hex()
        # Check against expected BCS representation.
        expected_public_key_bcs = (
            "41754bb6a4720a658bdd5f532995955db0971ad3519acbde2f1149c3857348006c"
            "1634cd4607073f2be4a6f2aadc2b866ddb117398a675f2096ed906b20e0bf2c901"
        )
        self.assertEqual(public_key_bcs, expected_public_key_bcs)
        # Get public key bytes representation.
        public_key_bytes = multisig_public_key.to_bytes()
        # Convert back to multisig class instance from bytes.
        multisig_public_key = MultiPublicKey.from_bytes(public_key_bytes)
        # Get public key BCS representation.
        serializer = Serializer()
        multisig_public_key.serialize(serializer)
        public_key_bcs = serializer.output().hex()
        # Assert BCS representation is the same.
        self.assertEqual(public_key_bcs, expected_public_key_bcs)
        # Have one signer sign arbitrary message.
        signature = private_key_2.sign(b"multisig")
        # Compose multisig signature.
        multisig_signature = MultiSignature.from_key_map(
            multisig_public_key, [(private_key_2.public_key(), signature)]
        )
        # Get signature BCS representation.
        serializer = Serializer()
        multisig_signature.serialize(serializer)
        multisig_signature_bcs = serializer.output().hex()
        # Check against expected BCS representation.
        expected_multisig_signature_bcs = (
            "4402e90d8f300d79963cb7159ffa6f620f5bba4af5d32a7176bfb5480b43897cf"
            "4886bbb4042182f4647c9b04f02dbf989966f0facceec52d22bdcc7ce631bfc0c"
            "40000000"
        )
        self.assertEqual(multisig_signature_bcs, expected_multisig_signature_bcs)
        deserializer = Deserializer(bytes.fromhex(expected_multisig_signature_bcs))
        multisig_signature_deserialized = deserializer.struct(MultiSignature)
        self.assertEqual(multisig_signature_deserialized, multisig_signature)

        self.assertTrue(multisig_public_key.verify(b"multisig", multisig_signature))

    def test_multisig_range_checks(self):
        # Generate public keys.
        keys = [
            PrivateKey.random().public_key() for x in range(MultiPublicKey.MAX_KEYS + 1)
        ]
        # Verify failure for initializing multisig instance with too few keys.
        with self.assertRaisesRegex(ValueError, "Must have between 2 and 32 keys."):
            MultiPublicKey([keys[0]], 1)
        # Verify failure for initializing multisig instance with too many keys.
        with self.assertRaisesRegex(ValueError, "Must have between 2 and 32 keys."):
            MultiPublicKey(keys, 1)
        # Verify failure for initializing multisig instance with small threshold.
        with self.assertRaisesRegex(ValueError, "Threshold must be between 1 and 4."):
            MultiPublicKey(keys[0:4], 0)
        # Verify failure for initializing multisig instance with large threshold.
        with self.assertRaisesRegex(ValueError, "Threshold must be between 1 and 4."):
            MultiPublicKey(keys[0:4], 5)
        # Verify failure for initializing from bytes with too few keys.
        with self.assertRaisesRegex(ValueError, "Must have between 2 and 32 keys."):
            MultiPublicKey.from_bytes(MultiPublicKey([keys[0]], 1).to_bytes())
        # Verify failure for initializing from bytes with too many keys.
        with self.assertRaisesRegex(ValueError, "Must have between 2 and 32 keys."):
            MultiPublicKey.from_bytes(MultiPublicKey(keys, 1).to_bytes())
        # Verify failure for initializing from bytes with small threshold.
        with self.assertRaisesRegex(ValueError, "Threshold must be between 1 and 4."):
            MultiPublicKey.from_bytes(MultiPublicKey(keys[0:4], 0).to_bytes())
        # Verify failure for initializing from bytes with large threshold.
        with self.assertRaisesRegex(ValueError, "Threshold must be between 1 and 4."):
            MultiPublicKey.from_bytes(MultiPublicKey(keys[0:4], 5).to_bytes())
