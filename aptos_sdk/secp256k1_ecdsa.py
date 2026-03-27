# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from typing import cast

from coincurve import PrivateKey as CoinPrivateKey

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
_secp256k1_mod = _load_module(
    "aptos_sdk.v2.crypto.secp256k1", os.path.join(_crypto_dir, "secp256k1.py")
)

_V2PrivateKey = _secp256k1_mod.Secp256k1PrivateKey
_V2PublicKey = _secp256k1_mod.Secp256k1PublicKey
_V2Signature = _secp256k1_mod.Secp256k1Signature

_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class PrivateKey(asymmetric_crypto.PrivateKey):
    LENGTH: int = 32

    _inner: _V2PrivateKey

    def __init__(self, key: CoinPrivateKey):
        self._inner = _V2PrivateKey(key)

    @property
    def key(self) -> CoinPrivateKey:
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
        :return: Parsed private key as bytes.
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
        :return: Parsed Secp256k1 private key.
        """
        return PrivateKey.from_hex(value, strict)

    def hex(self) -> str:
        return self._inner.hex()

    def aip80(self) -> str:
        return PrivateKey.format_private_key(
            self.hex(), asymmetric_crypto.PrivateKeyVariant.Secp256k1
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
    LENGTH: int = 64
    LENGTH_WITH_PREFIX_LENGTH: int = 65

    _inner: _V2PublicKey

    def __init__(self, raw: bytes):
        self._inner = _V2PublicKey(raw)

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

    def hex(self) -> str:
        return str(self._inner)

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            signature = cast(Signature, signature)
            # Delegate to v2's verify, wrapping our Signature's inner v2 signature
            return self._inner.verify(data, signature._inner)
        except Exception:
            return False

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

    def hex(self) -> str:
        return str(self._inner)

    @staticmethod
    def from_str(value: str) -> Signature:
        v2_sig = _V2Signature.from_str(value)
        sig = Signature.__new__(Signature)
        sig._inner = v2_sig
        return sig

    def data(self) -> bytes:
        return self._inner.data()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Signature:
        v2_sig = _V2Signature.deserialize(deserializer)
        sig = Signature.__new__(Signature)
        sig._inner = v2_sig
        return sig

    def serialize(self, serializer: Serializer):
        self._inner.serialize(serializer)


class Test(unittest.TestCase):
    def test_private_key_from_str(self):
        private_key_hex = PrivateKey.from_str(
            "0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4", False
        )
        private_key_with_prefix = PrivateKey.from_str(
            "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4",
            True,
        )
        private_key_bytes = PrivateKey.from_hex(
            bytes.fromhex(
                "306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
            ),
            False,
        )
        self.assertEqual(
            private_key_hex.hex(),
            private_key_with_prefix.hex(),
            private_key_bytes.hex(),
        )

    def test_private_key_aip80_formatting(self):
        private_key_with_prefix = "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        self.assertEqual(
            str(PrivateKey.from_str(private_key_with_prefix, True)),
            private_key_with_prefix,
        )

    def test_vectors(self):
        private_key_hex = "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        public_key_hex = "0x04210c9129e35337ff5d6488f90f18d842cf985f06e0baeff8df4bfb2ac4221863e2631b971a237b5db0aa71188e33250732dd461d56ee623cbe0426a5c2db79ef"
        signature_hex = "0xa539b0973e76fa99b2a864eebd5da950b4dfb399c7afe57ddb34130e454fc9db04dceb2c3d4260b8cc3d3952ab21b5d36c7dc76277fe3747764e6762d12bd9a9"
        data = b"Hello world"

        private_key = PrivateKey.from_str(private_key_hex)
        local_public_key = private_key.public_key()
        local_signature = private_key.sign(data)
        self.assertTrue(local_public_key.verify(data, local_signature))

        original_public_key = PublicKey.from_str(public_key_hex)
        self.assertTrue(original_public_key.verify(data, local_signature))
        self.assertEqual(public_key_hex[2:], local_public_key.to_crypto_bytes().hex())

        original_signature = Signature.from_str(signature_hex)
        self.assertTrue(original_public_key.verify(data, original_signature))

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

    def test_signatures_are_low_s(self):
        """All signatures must be low-S normalized per Aptos requirements."""
        half_n = _SECP256K1_ORDER // 2
        private_key = PrivateKey.random()
        for _ in range(50):
            sig = private_key.sign(b"low-s check")
            s = int.from_bytes(sig.data()[32:], "big")
            self.assertLessEqual(s, half_n)

    def test_high_s_signature_is_rejected_by_verify(self):
        """A high-S variant of a valid signature must fail Aptos-style verification."""
        private_key = PrivateKey.random()
        public_key = private_key.public_key()
        data = b"malleability check"

        sig = private_key.sign(data)
        self.assertTrue(public_key.verify(data, sig))

        sig_bytes = sig.data()
        r = int.from_bytes(sig_bytes[:32], "big")
        low_s = int.from_bytes(sig_bytes[32:], "big")
        high_s = _SECP256K1_ORDER - low_s
        flipped = Signature(r.to_bytes(32, "big") + high_s.to_bytes(32, "big"))
        self.assertFalse(public_key.verify(data, flipped))
