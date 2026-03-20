# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest
from typing import cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from . import asymmetric_crypto
from .bcs import Deserializer, Serializer

_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class PrivateKey(asymmetric_crypto.PrivateKey):
    LENGTH: int = 32

    key: ec.EllipticCurvePrivateKey

    def __init__(self, key: ec.EllipticCurvePrivateKey):
        self.key = key

    def __eq__(self, other: object):
        if not isinstance(other, PrivateKey):
            return NotImplemented
        return (
            self.key.private_numbers().private_value
            == other.key.private_numbers().private_value
        )

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
        parsed_value = PrivateKey.parse_hex_input(
            value, asymmetric_crypto.PrivateKeyVariant.Secp256k1, strict
        )
        if len(parsed_value) != PrivateKey.LENGTH:
            raise Exception("Length mismatch")
        private_int = int.from_bytes(parsed_value, "big")
        return PrivateKey(ec.derive_private_key(private_int, ec.SECP256K1()))

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
        raw = self.key.private_numbers().private_value.to_bytes(
            PrivateKey.LENGTH, "big"
        )
        return f"0x{raw.hex()}"

    def aip80(self) -> str:
        return PrivateKey.format_private_key(
            self.hex(), asymmetric_crypto.PrivateKeyVariant.Secp256k1
        )

    def public_key(self) -> PublicKey:
        return PublicKey(self.key.public_key())

    @staticmethod
    def random() -> PrivateKey:
        return PrivateKey(ec.generate_private_key(ec.SECP256K1()))

    def sign(self, data: bytes) -> Signature:
        der_sig = self.key.sign(data, ec.ECDSA(hashes.SHA3_256()))
        r, s = decode_dss_signature(der_sig)
        # Normalize to low-S: only s < n // 2 is valid
        n = _SECP256K1_ORDER
        if s > (n // 2):
            s = n - s
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return Signature(sig_bytes)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PrivateKey:
        key = deserializer.to_bytes()
        if len(key) != PrivateKey.LENGTH:
            raise Exception("Length mismatch")
        private_int = int.from_bytes(key, "big")
        return PrivateKey(ec.derive_private_key(private_int, ec.SECP256K1()))

    def serialize(self, serializer: Serializer):
        raw = self.key.private_numbers().private_value.to_bytes(
            PrivateKey.LENGTH, "big"
        )
        serializer.to_bytes(raw)


class PublicKey(asymmetric_crypto.PublicKey):
    LENGTH: int = 64
    LENGTH_WITH_PREFIX_LENGTH: int = 65

    key: ec.EllipticCurvePublicKey

    def __init__(self, key: ec.EllipticCurvePublicKey):
        self.key = key

    def __eq__(self, other: object):
        if not isinstance(other, PublicKey):
            return NotImplemented
        self_nums = self.key.public_numbers()
        other_nums = other.key.public_numbers()
        return self_nums.x == other_nums.x and self_nums.y == other_nums.y

    def __str__(self) -> str:
        return self.hex()

    @staticmethod
    def from_str(value: str) -> PublicKey:
        if value[0:2] == "0x":
            value = value[2:]
        # Hex values are twice the length of their binary counterpart.
        if (
            len(value) != PublicKey.LENGTH * 2
            and len(value) != PublicKey.LENGTH_WITH_PREFIX_LENGTH * 2
        ):
            raise Exception("Length mismatch")
        raw = bytes.fromhex(value)
        if len(raw) == PublicKey.LENGTH:
            raw = b"\x04" + raw
        return PublicKey(
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw)
        )

    def _raw_bytes(self) -> bytes:
        nums = self.key.public_numbers()
        return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def hex(self) -> str:
        return f"0x04{self._raw_bytes().hex()}"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            signature = cast(Signature, signature)
            sig_data = signature.data()
            r = int.from_bytes(sig_data[:32], "big")
            s = int.from_bytes(sig_data[32:], "big")
            der_sig = encode_dss_signature(r, s)
            self.key.verify(der_sig, data, ec.ECDSA(hashes.SHA3_256()))
        except Exception:
            return False
        return True

    def to_crypto_bytes(self) -> bytes:
        return b"\x04" + self._raw_bytes()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PublicKey:
        key = deserializer.to_bytes()
        if len(key) == PublicKey.LENGTH_WITH_PREFIX_LENGTH:
            if key[0] != 0x04:
                raise Exception("Invalid uncompressed point prefix")
            key = key[1:]
        elif len(key) != PublicKey.LENGTH:
            raise Exception("Length mismatch")
        return PublicKey(
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x04" + key)
        )

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self.to_crypto_bytes())


class Signature(asymmetric_crypto.Signature):
    LENGTH: int = 64

    signature: bytes

    def __init__(self, signature: bytes):
        self.signature = signature

    def __eq__(self, other: object):
        if not isinstance(other, Signature):
            return NotImplemented
        return self.signature == other.signature

    def __str__(self) -> str:
        return self.hex()

    def hex(self) -> str:
        return f"0x{self.signature.hex()}"

    @staticmethod
    def from_str(value: str) -> Signature:
        if value[0:2] == "0x":
            value = value[2:]
        if len(value) != Signature.LENGTH * 2:
            raise Exception("Length mismatch")
        return Signature(bytes.fromhex(value))

    def data(self) -> bytes:
        return self.signature

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Signature:
        signature = deserializer.to_bytes()
        if len(signature) != Signature.LENGTH:
            raise Exception("Length mismatch")

        return Signature(signature)

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self.signature)


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
