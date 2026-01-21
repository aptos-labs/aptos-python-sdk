# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import unittest
from typing import cast

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from . import asymmetric_crypto
from .bcs import Deserializer, Serializer


class PrivateKey(asymmetric_crypto.PrivateKey):
    LENGTH: int = 32

    key: ec.EllipticCurvePrivateKey

    def __init__(self, key: ec.EllipticCurvePrivateKey):
        self.key = key

    def __eq__(self, other: object):
        if not isinstance(other, PrivateKey):
            return NotImplemented
        # Compare private values
        return self._to_bytes() == other._to_bytes()

    def __str__(self):
        return self.aip80()

    def _to_bytes(self) -> bytes:
        """Convert private key to raw 32-byte representation."""
        private_numbers = self.key.private_numbers()
        return private_numbers.private_value.to_bytes(PrivateKey.LENGTH, byteorder="big")

    @staticmethod
    def _from_bytes(key_bytes: bytes) -> ec.EllipticCurvePrivateKey:
        """Create private key from raw 32-byte representation."""
        if len(key_bytes) != PrivateKey.LENGTH:
            raise Exception("Length mismatch")
        private_value = int.from_bytes(key_bytes, byteorder="big")
        return ec.derive_private_key(private_value, ec.SECP256K1())

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
        if len(parsed_value.hex()) != PrivateKey.LENGTH * 2:
            raise Exception("Length mismatch")
        return PrivateKey(PrivateKey._from_bytes(parsed_value))

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
        return f"0x{self._to_bytes().hex()}"

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
        # Use deterministic ECDSA (RFC 6979) with SHA3-256
        signature_der = self.key.sign(
            data, ec.ECDSA(hashes.SHA3_256())
        )
        # Decode DER signature to get r and s
        r, s = decode_dss_signature(signature_der)

        # SECP256K1 curve order
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

        # The signature is valid for both s and -s, normalization ensures that only s < n // 2 is valid
        if s > (n // 2):
            s = n - s

        # Encode r and s as raw bytes (32 bytes each)
        sig_bytes = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
        return Signature(sig_bytes)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PrivateKey:
        key = deserializer.to_bytes()
        if len(key) != PrivateKey.LENGTH:
            raise Exception("Length mismatch")

        return PrivateKey(PrivateKey._from_bytes(key))

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self._to_bytes())


class PublicKey(asymmetric_crypto.PublicKey):
    LENGTH: int = 64
    LENGTH_WITH_PREFIX_LENGTH: int = 65

    key: ec.EllipticCurvePublicKey

    def __init__(self, key: ec.EllipticCurvePublicKey):
        self.key = key

    def __eq__(self, other: object):
        if not isinstance(other, PublicKey):
            return NotImplemented
        # Compare public key bytes
        return self.to_crypto_bytes() == other.to_crypto_bytes()

    def __str__(self) -> str:
        return self.hex()

    @staticmethod
    def _from_uncompressed_bytes(key_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """Create public key from uncompressed format (64 or 65 bytes)."""
        # Handle optional 0x04 prefix
        if len(key_bytes) == PublicKey.LENGTH_WITH_PREFIX_LENGTH:
            if key_bytes[0] != 0x04:
                raise Exception("Invalid public key format")
            key_bytes = key_bytes[1:]
        elif len(key_bytes) != PublicKey.LENGTH:
            raise Exception("Length mismatch")

        # Split into x and y coordinates
        x = int.from_bytes(key_bytes[:32], byteorder="big")
        y = int.from_bytes(key_bytes[32:], byteorder="big")

        # Create public key from numbers
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
        return public_numbers.public_key()

    def _to_uncompressed_bytes(self) -> bytes:
        """Convert public key to uncompressed format (64 bytes, no prefix)."""
        public_numbers = self.key.public_numbers()
        x_bytes = public_numbers.x.to_bytes(32, byteorder="big")
        y_bytes = public_numbers.y.to_bytes(32, byteorder="big")
        return x_bytes + y_bytes

    @staticmethod
    def from_str(value: str) -> PublicKey:
        if value[0:2] == "0x":
            value = value[2:]
        # We are measuring hex values which are twice the length of their binary counterpart.
        if (
            len(value) != PublicKey.LENGTH * 2
            and len(value) != PublicKey.LENGTH_WITH_PREFIX_LENGTH * 2
        ):
            raise Exception("Length mismatch")
        return PublicKey(PublicKey._from_uncompressed_bytes(bytes.fromhex(value)))

    def hex(self) -> str:
        return f"0x04{self._to_uncompressed_bytes().hex()}"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            signature = cast(Signature, signature)
            sig_bytes = signature.data()

            # Parse r and s from raw signature bytes (32 bytes each)
            r = int.from_bytes(sig_bytes[:32], byteorder="big")
            s = int.from_bytes(sig_bytes[32:], byteorder="big")

            # Encode as DER for verification
            sig_der = encode_dss_signature(r, s)

            self.key.verify(sig_der, data, ec.ECDSA(hashes.SHA3_256()))
        except Exception:
            return False
        return True

    def to_crypto_bytes(self) -> bytes:
        return b"\x04" + self._to_uncompressed_bytes()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PublicKey:
        key = deserializer.to_bytes()
        if len(key) != PublicKey.LENGTH:
            # Some standards apply an extra byte to represent that this is a 64-byte key
            if len(key) == PublicKey.LENGTH_WITH_PREFIX_LENGTH:
                key = key[1:]
            else:
                raise Exception("Length mismatch")

        return PublicKey(PublicKey._from_uncompressed_bytes(key))

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
