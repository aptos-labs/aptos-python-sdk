# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for Secp256k1-ECDSA cryptography module.
"""

import pytest
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.secp256k1_ecdsa import PrivateKey, PublicKey, Signature


class TestPrivateKey:
    """Tests for Secp256k1 PrivateKey."""

    def test_private_key_from_str(self):
        """Test private key parsing from various string formats."""
        private_key_hex = PrivateKey.from_str(
            "0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4",
            False,
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
        assert (
            private_key_hex.hex()
            == private_key_with_prefix.hex()
            == private_key_bytes.hex()
        )

    def test_private_key_aip80_formatting(self):
        """Test AIP-80 compliant private key string formatting."""
        private_key_with_prefix = "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        assert (
            str(PrivateKey.from_str(private_key_with_prefix, True))
            == private_key_with_prefix
        )


class TestVectors:
    """Test vectors for Secp256k1."""

    def test_vectors(self):
        """Test against known test vectors."""
        private_key_hex = "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        public_key_hex = "0x04210c9129e35337ff5d6488f90f18d842cf985f06e0baeff8df4bfb2ac4221863e2631b971a237b5db0aa71188e33250732dd461d56ee623cbe0426a5c2db79ef"
        signature_hex = "0xa539b0973e76fa99b2a864eebd5da950b4dfb399c7afe57ddb34130e454fc9db04dceb2c3d4260b8cc3d3952ab21b5d36c7dc76277fe3747764e6762d12bd9a9"
        data = b"Hello world"

        private_key = PrivateKey.from_str(private_key_hex)
        local_public_key = private_key.public_key()
        local_signature = private_key.sign(data)
        assert local_public_key.verify(data, local_signature)

        original_public_key = PublicKey.from_str(public_key_hex)
        assert original_public_key.verify(data, local_signature)
        assert public_key_hex[2:] == local_public_key.to_crypto_bytes().hex()

        original_signature = Signature.from_str(signature_hex)
        assert original_public_key.verify(data, original_signature)


class TestSignAndVerify:
    """Tests for signing and verification."""

    def test_sign_and_verify(self):
        """Test that signed messages can be verified."""
        in_value = b"test_message"
        private_key = PrivateKey.random()
        public_key = private_key.public_key()
        signature = private_key.sign(in_value)
        assert public_key.verify(in_value, signature)


class TestSerialization:
    """Tests for BCS serialization."""

    def test_private_key_serialization(self):
        """Test private key round-trip through BCS."""
        private_key = PrivateKey.random()
        ser = Serializer()
        private_key.serialize(ser)
        ser_private_key = PrivateKey.deserialize(Deserializer(ser.output()))
        assert private_key == ser_private_key

    def test_public_key_serialization(self):
        """Test public key round-trip through BCS."""
        private_key = PrivateKey.random()
        public_key = private_key.public_key()
        ser = Serializer()
        public_key.serialize(ser)
        ser_public_key = PublicKey.deserialize(Deserializer(ser.output()))
        assert public_key == ser_public_key

    def test_signature_key_serialization(self):
        """Test signature round-trip through BCS."""
        private_key = PrivateKey.random()
        in_value = b"another_message"
        signature = private_key.sign(in_value)
        ser = Serializer()
        signature.serialize(ser)
        ser_signature = Signature.deserialize(Deserializer(ser.output()))
        assert signature == ser_signature

