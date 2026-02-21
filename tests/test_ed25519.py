# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.ed25519 — Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
MultiEd25519PublicKey, and MultiEd25519Signature.
"""

import pytest

from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    Ed25519Signature,
    MultiEd25519PublicKey,
    MultiEd25519Signature,
    MultiPublicKey,
    MultiSignature,
    PrivateKey,
    PublicKey,
    Signature,
)
from aptos_sdk.errors import (
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    InvalidSignatureError,
)

# ---------------------------------------------------------------------------
# Ed25519PrivateKey
# ---------------------------------------------------------------------------


class TestEd25519PrivateKey:
    def test_generate_returns_private_key(self):
        key = Ed25519PrivateKey.generate()
        assert isinstance(key, Ed25519PrivateKey)

    def test_generate_produces_unique_keys(self):
        k1 = Ed25519PrivateKey.generate()
        k2 = Ed25519PrivateKey.generate()
        assert k1 != k2

    def test_from_bytes_roundtrip(self):
        key = Ed25519PrivateKey.generate()
        raw = key.to_bytes()
        restored = Ed25519PrivateKey.from_bytes(raw)
        assert key == restored

    def test_from_bytes_wrong_length_raises(self):
        with pytest.raises(InvalidPrivateKeyError):
            Ed25519PrivateKey.from_bytes(b"\x00" * 31)

    def test_from_bytes_empty_raises(self):
        with pytest.raises(InvalidPrivateKeyError):
            Ed25519PrivateKey.from_bytes(b"")

    def test_from_hex_with_prefix(self):
        key = Ed25519PrivateKey.generate()
        hex_str = key.to_hex()  # "0x..." form
        assert hex_str.startswith("0x")
        restored = Ed25519PrivateKey.from_hex(hex_str)
        assert key == restored

    def test_from_hex_without_prefix(self):
        key = Ed25519PrivateKey.generate()
        raw_hex = key.to_bytes().hex()
        restored = Ed25519PrivateKey.from_hex(raw_hex)
        assert key == restored

    def test_to_aip80_format(self):
        key = Ed25519PrivateKey.generate()
        aip80 = key.to_aip80()
        assert aip80.startswith("ed25519-priv-0x")

    def test_from_aip80_roundtrip(self):
        key = Ed25519PrivateKey.generate()
        aip80 = key.to_aip80()
        restored = Ed25519PrivateKey.from_aip80(aip80)
        assert key == restored

    def test_str_is_aip80(self):
        key = Ed25519PrivateKey.generate()
        assert str(key) == key.to_aip80()

    def test_repr_masks_key_material(self):
        key = Ed25519PrivateKey.generate()
        r = repr(key)
        assert "***" in r
        assert key.to_hex() not in r

    def test_equality(self):
        key = Ed25519PrivateKey.generate()
        raw = key.to_bytes()
        key2 = Ed25519PrivateKey.from_bytes(raw)
        assert key == key2

    def test_inequality(self):
        k1 = Ed25519PrivateKey.generate()
        k2 = Ed25519PrivateKey.generate()
        assert k1 != k2

    def test_public_key_derivation(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        assert isinstance(pub, Ed25519PublicKey)
        assert len(pub.to_bytes()) == 32

    def test_bcs_round_trip(self):
        original = Ed25519PrivateKey.generate()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Ed25519PrivateKey.deserialize(der)
        assert original == restored

    def test_strict_aip80_rejects_plain_hex(self):
        key = Ed25519PrivateKey.generate()
        with pytest.raises(Exception):
            Ed25519PrivateKey.from_hex(key.to_hex(), strict=True)

    def test_random_alias(self):
        key = Ed25519PrivateKey.random()
        assert isinstance(key, Ed25519PrivateKey)

    def test_variant_is_ed25519(self):
        from aptos_sdk.asymmetric_crypto import PrivateKeyVariant

        assert Ed25519PrivateKey.variant() == PrivateKeyVariant.ED25519


# ---------------------------------------------------------------------------
# Ed25519PublicKey
# ---------------------------------------------------------------------------


class TestEd25519PublicKey:
    def test_from_bytes_roundtrip(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        raw = pub.to_bytes()
        restored = Ed25519PublicKey.from_bytes(raw)
        assert pub == restored

    def test_from_bytes_wrong_length_raises(self):
        with pytest.raises(InvalidPublicKeyError):
            Ed25519PublicKey.from_bytes(b"\x00" * 31)

    def test_to_hex_has_prefix(self):
        pub = Ed25519PrivateKey.generate().public_key()
        assert pub.to_hex().startswith("0x")
        assert len(pub.to_hex()) == 2 + 64  # "0x" + 64 hex chars

    def test_to_crypto_bytes_equals_to_bytes(self):
        pub = Ed25519PrivateKey.generate().public_key()
        assert pub.to_crypto_bytes() == pub.to_bytes()

    def test_auth_key_is_32_bytes(self):
        pub = Ed25519PrivateKey.generate().public_key()
        assert len(pub.auth_key()) == 32

    def test_repr(self):
        pub = Ed25519PrivateKey.generate().public_key()
        r = repr(pub)
        assert "Ed25519PublicKey" in r

    def test_hashable(self):
        pub = Ed25519PrivateKey.generate().public_key()
        s = {pub, pub}
        assert len(s) == 1

    def test_bcs_round_trip(self):
        original = Ed25519PrivateKey.generate().public_key()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Ed25519PublicKey.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# Ed25519Signature
# ---------------------------------------------------------------------------


class TestEd25519Signature:
    def test_sign_and_verify(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        msg = b"hello aptos"
        sig = priv.sign(msg)
        assert pub.verify(msg, sig)

    def test_verify_wrong_message_fails(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        msg = b"hello aptos"
        sig = priv.sign(msg)
        assert not pub.verify(b"wrong message", sig)

    def test_verify_wrong_key_fails(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"hello aptos"
        sig = priv1.sign(msg)
        assert not priv2.public_key().verify(msg, sig)

    def test_from_bytes_roundtrip(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"test")
        raw = sig.to_bytes()
        restored = Ed25519Signature.from_bytes(raw)
        assert sig == restored

    def test_wrong_length_raises(self):
        with pytest.raises(InvalidSignatureError):
            Ed25519Signature.from_bytes(b"\x00" * 63)

    def test_to_hex_has_prefix(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"test")
        assert sig.to_hex().startswith("0x")
        assert len(sig.to_hex()) == 2 + 128  # "0x" + 128 hex chars

    def test_from_str_with_prefix(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"test")
        hex_str = sig.to_hex()
        restored = Ed25519Signature.from_str(hex_str)
        assert sig == restored

    def test_data_legacy_method(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"test")
        assert sig.data() == sig.to_bytes()

    def test_bcs_round_trip(self):
        priv = Ed25519PrivateKey.generate()
        original = priv.sign(b"hello")
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Ed25519Signature.deserialize(der)
        assert original == restored

    def test_repr(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"test")
        r = repr(sig)
        assert "Ed25519Signature" in r


# ---------------------------------------------------------------------------
# MultiEd25519PublicKey
# ---------------------------------------------------------------------------


class TestMultiEd25519PublicKey:
    def _make_keys(self, n: int):
        return [Ed25519PrivateKey.generate().public_key() for _ in range(n)]

    def test_construction_2of2(self):
        keys = self._make_keys(2)
        multi = MultiEd25519PublicKey(keys, 2)
        assert multi.threshold == 2
        assert len(multi.keys) == 2

    def test_construction_1of3(self):
        keys = self._make_keys(3)
        multi = MultiEd25519PublicKey(keys, 1)
        assert multi.threshold == 1

    def test_too_few_keys_raises(self):
        keys = self._make_keys(1)
        with pytest.raises(ValueError):
            MultiEd25519PublicKey(keys, 1)

    def test_threshold_too_high_raises(self):
        keys = self._make_keys(2)
        with pytest.raises(ValueError):
            MultiEd25519PublicKey(keys, 3)

    def test_threshold_zero_raises(self):
        keys = self._make_keys(2)
        with pytest.raises(ValueError):
            MultiEd25519PublicKey(keys, 0)

    def test_str_contains_threshold(self):
        keys = self._make_keys(2)
        multi = MultiEd25519PublicKey(keys, 2)
        assert "2" in str(multi)

    def test_to_crypto_bytes_length(self):
        n = 2
        keys = self._make_keys(n)
        multi = MultiEd25519PublicKey(keys, 2)
        # n * 32 key bytes + 1 threshold byte
        assert len(multi.to_crypto_bytes()) == n * 32 + 1

    def test_from_crypto_bytes_roundtrip(self):
        keys = self._make_keys(2)
        multi = MultiEd25519PublicKey(keys, 2)
        raw = multi.to_crypto_bytes()
        restored = MultiEd25519PublicKey.from_crypto_bytes(raw)
        assert multi == restored

    def test_bcs_round_trip(self):
        keys = self._make_keys(2)
        original = MultiEd25519PublicKey(keys, 2)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MultiEd25519PublicKey.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# MultiEd25519Signature
# ---------------------------------------------------------------------------


class TestMultiEd25519Signature:
    def _make_pairs(self, n: int):
        return [
            (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate().public_key())
            for _ in range(n)
        ]

    def test_construction(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"msg")
        multi_sig = MultiEd25519Signature([(0, sig)])
        assert len(multi_sig.signatures) == 1

    def test_index_too_high_raises(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"msg")
        with pytest.raises(ValueError):
            MultiEd25519Signature([(32, sig)])  # 32 >= BITMAP_NUM_OF_BYTES * 8

    def test_equality(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"msg")
        a = MultiEd25519Signature([(0, sig)])
        b = MultiEd25519Signature([(0, sig)])
        assert a == b

    def test_bcs_round_trip(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"test message"
        sig1 = priv1.sign(msg)
        sig2 = priv2.sign(msg)
        original = MultiEd25519Signature([(0, sig1), (1, sig2)])
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MultiEd25519Signature.deserialize(der)
        assert original == restored

    def test_from_key_map(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        pub1 = priv1.public_key()
        pub2 = priv2.public_key()
        multi_pub = MultiEd25519PublicKey([pub1, pub2], 2)
        msg = b"hello multi"
        sig1 = priv1.sign(msg)
        sig2 = priv2.sign(msg)
        multi_sig = MultiEd25519Signature.from_key_map(
            multi_pub, [(pub1, sig1), (pub2, sig2)]
        )
        assert len(multi_sig.signatures) == 2

    def test_verify_succeeds_with_threshold(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        pub1 = priv1.public_key()
        pub2 = priv2.public_key()
        multi_pub = MultiEd25519PublicKey([pub1, pub2], 2)
        msg = b"verify me"
        sig1 = priv1.sign(msg)
        sig2 = priv2.sign(msg)
        multi_sig = MultiEd25519Signature([(0, sig1), (1, sig2)])
        assert multi_pub.verify(msg, multi_sig)


# ---------------------------------------------------------------------------
# Legacy aliases
# ---------------------------------------------------------------------------


class TestLegacyAliases:
    def test_private_key_alias(self):
        assert PrivateKey is Ed25519PrivateKey

    def test_public_key_alias(self):
        assert PublicKey is Ed25519PublicKey

    def test_signature_alias(self):
        assert Signature is Ed25519Signature

    def test_multi_public_key_alias(self):
        assert MultiPublicKey is MultiEd25519PublicKey

    def test_multi_signature_alias(self):
        assert MultiSignature is MultiEd25519Signature
