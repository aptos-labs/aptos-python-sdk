# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.secp256k1_ecdsa — Secp256k1PrivateKey, Secp256k1PublicKey,
Secp256k1Signature.
"""

import pytest

from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.errors import (
    InvalidLengthError,
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    InvalidSignatureError,
)
from aptos_sdk.secp256k1_ecdsa import (
    Secp256k1PrivateKey,
    Secp256k1PublicKey,
    Secp256k1Signature,
    secp256k1_auth_key,
)

# ---------------------------------------------------------------------------
# Secp256k1PrivateKey
# ---------------------------------------------------------------------------


class TestSecp256k1PrivateKey:
    def test_generate(self):
        key = Secp256k1PrivateKey.generate()
        assert isinstance(key, Secp256k1PrivateKey)

    def test_generate_unique(self):
        k1 = Secp256k1PrivateKey.generate()
        k2 = Secp256k1PrivateKey.generate()
        assert k1 != k2

    def test_to_bytes_is_32_bytes(self):
        key = Secp256k1PrivateKey.generate()
        assert len(key.to_bytes()) == 32

    def test_from_bytes_roundtrip(self):
        key = Secp256k1PrivateKey.generate()
        restored = Secp256k1PrivateKey.from_bytes(key.to_bytes())
        assert key == restored

    def test_from_bytes_wrong_length_raises(self):
        with pytest.raises(InvalidPrivateKeyError):
            Secp256k1PrivateKey.from_bytes(b"\x00" * 31)

    def test_from_bytes_empty_raises(self):
        with pytest.raises(InvalidPrivateKeyError):
            Secp256k1PrivateKey.from_bytes(b"")

    def test_from_hex_with_prefix(self):
        key = Secp256k1PrivateKey.generate()
        restored = Secp256k1PrivateKey.from_hex(key.to_hex())
        assert key == restored

    def test_from_hex_without_prefix(self):
        key = Secp256k1PrivateKey.generate()
        raw_hex = key.to_bytes().hex()
        restored = Secp256k1PrivateKey.from_hex(raw_hex)
        assert key == restored

    def test_to_aip80_format(self):
        key = Secp256k1PrivateKey.generate()
        aip80 = key.to_aip80()
        assert aip80.startswith("secp256k1-priv-0x")
        assert len(aip80) == len("secp256k1-priv-0x") + 64

    def test_from_str_aip80_roundtrip(self):
        key = Secp256k1PrivateKey.generate()
        aip80 = key.to_aip80()
        restored = Secp256k1PrivateKey.from_str(aip80)
        assert key == restored

    def test_str_is_aip80(self):
        key = Secp256k1PrivateKey.generate()
        assert str(key) == key.to_aip80()

    def test_repr_masks_key_material(self):
        key = Secp256k1PrivateKey.generate()
        r = repr(key)
        assert "***" in r
        assert key.to_hex() not in r

    def test_public_key_derivation(self):
        key = Secp256k1PrivateKey.generate()
        pub = key.public_key()
        assert isinstance(pub, Secp256k1PublicKey)

    def test_bcs_round_trip(self):
        original = Secp256k1PrivateKey.generate()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Secp256k1PrivateKey.deserialize(der)
        assert original == restored

    def test_strict_aip80_mode_rejects_plain_hex(self):
        key = Secp256k1PrivateKey.generate()
        with pytest.raises(Exception):
            Secp256k1PrivateKey.from_str(key.to_hex(), strict=True)


# ---------------------------------------------------------------------------
# Secp256k1PublicKey
# ---------------------------------------------------------------------------


class TestSecp256k1PublicKey:
    def test_to_bytes_is_64_bytes(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        assert len(pub.to_bytes()) == 64

    def test_to_crypto_bytes_is_65_bytes(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        crypto_bytes = pub.to_crypto_bytes()
        assert len(crypto_bytes) == 65
        assert crypto_bytes[0] == 0x04  # uncompressed prefix

    def test_to_hex_has_0x04_prefix(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        assert pub.to_hex().startswith("0x04")
        assert len(pub.to_hex()) == 4 + 128  # "0x04" + 128 hex chars

    def test_from_bytes_64_byte_raw(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        raw = pub.to_bytes()  # 64 bytes without prefix
        restored = Secp256k1PublicKey.from_bytes(raw)
        assert pub == restored

    def test_from_bytes_65_byte_uncompressed(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        uncompressed = pub.to_crypto_bytes()  # 65 bytes with 0x04 prefix
        restored = Secp256k1PublicKey.from_bytes(uncompressed)
        assert pub == restored

    def test_from_bytes_wrong_length_raises(self):
        with pytest.raises((InvalidLengthError, InvalidPublicKeyError)):
            Secp256k1PublicKey.from_bytes(b"\x00" * 32)

    def test_from_str_roundtrip(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        restored = Secp256k1PublicKey.from_str(pub.to_hex())
        assert pub == restored

    def test_repr(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        r = repr(pub)
        assert "Secp256k1PublicKey" in r

    def test_equality(self):
        priv = Secp256k1PrivateKey.generate()
        pub1 = priv.public_key()
        pub2 = Secp256k1PublicKey.from_bytes(pub1.to_bytes())
        assert pub1 == pub2

    def test_bcs_round_trip(self):
        priv = Secp256k1PrivateKey.generate()
        original = priv.public_key()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Secp256k1PublicKey.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# Secp256k1Signature
# ---------------------------------------------------------------------------


class TestSecp256k1Signature:
    def test_sign_and_verify(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        msg = b"hello secp256k1"
        sig = priv.sign(msg)
        assert pub.verify(msg, sig)

    def test_verify_wrong_message_fails(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        sig = priv.sign(b"original message")
        assert not pub.verify(b"different message", sig)

    def test_verify_wrong_key_fails(self):
        priv1 = Secp256k1PrivateKey.generate()
        priv2 = Secp256k1PrivateKey.generate()
        sig = priv1.sign(b"test")
        assert not priv2.public_key().verify(b"test", sig)

    def test_signature_is_64_bytes(self):
        priv = Secp256k1PrivateKey.generate()
        sig = priv.sign(b"test")
        assert len(sig.to_bytes()) == 64

    def test_from_bytes_roundtrip(self):
        priv = Secp256k1PrivateKey.generate()
        sig = priv.sign(b"test")
        raw = sig.to_bytes()
        restored = Secp256k1Signature.from_bytes(raw)
        assert sig == restored

    def test_from_bytes_wrong_length_raises(self):
        with pytest.raises(InvalidSignatureError):
            Secp256k1Signature.from_bytes(b"\x00" * 63)

    def test_to_hex_format(self):
        priv = Secp256k1PrivateKey.generate()
        sig = priv.sign(b"test")
        hex_str = sig.to_hex()
        assert hex_str.startswith("0x")
        assert len(hex_str) == 2 + 128

    def test_from_str_roundtrip(self):
        priv = Secp256k1PrivateKey.generate()
        sig = priv.sign(b"test")
        hex_str = sig.to_hex()
        restored = Secp256k1Signature.from_str(hex_str)
        assert sig == restored

    def test_data_legacy_method(self):
        priv = Secp256k1PrivateKey.generate()
        sig = priv.sign(b"test")
        assert sig.data() == sig.to_bytes()

    def test_repr(self):
        priv = Secp256k1PrivateKey.generate()
        sig = priv.sign(b"test")
        r = repr(sig)
        assert "Secp256k1Signature" in r

    def test_bcs_round_trip(self):
        priv = Secp256k1PrivateKey.generate()
        original = priv.sign(b"round trip")
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Secp256k1Signature.deserialize(der)
        assert original == restored

    def test_low_s_normalization(self):
        """Signatures produced by sign() should always be low-S canonical."""
        from ecdsa import SECP256k1, util

        priv = Secp256k1PrivateKey.generate()
        for msg in [b"test1", b"test2", b"test3"]:
            sig = priv.sign(msg)
            n = SECP256k1.generator.order()
            raw = sig.to_bytes()
            r, s = util.sigdecode_string(raw, n)
            assert s <= n // 2, f"Signature has high-S value for message {msg!r}"


# ---------------------------------------------------------------------------
# secp256k1_auth_key helper
# ---------------------------------------------------------------------------


class TestSecp256k1AuthKey:
    def test_auth_key_is_32_bytes(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        key = secp256k1_auth_key(pub)
        assert len(key) == 32

    def test_auth_key_deterministic(self):
        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        assert secp256k1_auth_key(pub) == secp256k1_auth_key(pub)

    def test_auth_key_matches_manual_derivation(self):
        from aptos_sdk.hashing import sha3_256

        priv = Secp256k1PrivateKey.generate()
        pub = priv.public_key()
        expected = sha3_256(pub.to_crypto_bytes() + b"\x01")
        assert secp256k1_auth_key(pub) == expected
