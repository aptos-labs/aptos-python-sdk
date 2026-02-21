# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.crypto_wrapper — AnyPublicKey, AnySignature,
MultiKeyPublicKey, MultiKeySignature, and index_to_bitmap_value.
"""

import pytest

from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.crypto_wrapper import (
    AnyPublicKey,
    AnySignature,
    MultiKeyPublicKey,
    MultiKeySignature,
    index_to_bitmap_value,
)
from aptos_sdk.ed25519 import Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature
from aptos_sdk.errors import CryptoError, InvalidPublicKeyError, InvalidSignatureError
from aptos_sdk.secp256k1_ecdsa import (
    Secp256k1PrivateKey,
    Secp256k1PublicKey,
    Secp256k1Signature,
)

# ---------------------------------------------------------------------------
# index_to_bitmap_value
# ---------------------------------------------------------------------------


class TestIndexToBitmapValue:
    def test_index_0_is_msb_of_byte_0(self):
        # bit 7 of byte 0 → 0x80 = 128
        assert index_to_bitmap_value(0) == 128

    def test_index_1(self):
        # bit 6 of byte 0 → 0x40 = 64
        assert index_to_bitmap_value(1) == 64

    def test_index_7(self):
        # bit 0 of byte 0 → 0x01 = 1
        assert index_to_bitmap_value(7) == 1

    def test_index_8_is_msb_of_byte_1(self):
        # bit 7 of byte 1 → 0x8000 = 32768
        assert index_to_bitmap_value(8) == 32768

    def test_index_9(self):
        # bit 6 of byte 1 → 0x4000 = 16384
        assert index_to_bitmap_value(9) == 16384

    def test_index_values_are_unique(self):
        values = [index_to_bitmap_value(i) for i in range(16)]
        assert len(set(values)) == 16


# ---------------------------------------------------------------------------
# AnyPublicKey
# ---------------------------------------------------------------------------


class TestAnyPublicKey:
    def _ed25519_pub(self) -> Ed25519PublicKey:
        return Ed25519PrivateKey.generate().public_key()

    def _secp256k1_pub(self) -> Secp256k1PublicKey:
        return Secp256k1PrivateKey.generate().public_key()

    def test_wraps_ed25519(self):
        pub = self._ed25519_pub()
        any_pub = AnyPublicKey(pub)
        assert any_pub.variant == AnyPublicKey.ED25519
        assert any_pub.public_key == pub

    def test_wraps_secp256k1(self):
        pub = self._secp256k1_pub()
        any_pub = AnyPublicKey(pub)
        assert any_pub.variant == AnyPublicKey.SECP256K1_ECDSA
        assert any_pub.public_key == pub

    def test_invalid_type_raises(self):
        with pytest.raises(InvalidPublicKeyError):
            AnyPublicKey("not a key")  # type: ignore[arg-type]

    def test_ed25519_variant_constant(self):
        assert AnyPublicKey.ED25519 == 0

    def test_secp256k1_variant_constant(self):
        assert AnyPublicKey.SECP256K1_ECDSA == 1

    def test_equality_same(self):
        pub = self._ed25519_pub()
        a = AnyPublicKey(pub)
        b = AnyPublicKey(pub)
        assert a == b

    def test_inequality_different_type(self):
        ed_pub = self._ed25519_pub()
        sec_pub = self._secp256k1_pub()
        a = AnyPublicKey(ed_pub)
        b = AnyPublicKey(sec_pub)
        assert a != b

    def test_hashable(self):
        pub = self._ed25519_pub()
        any_pub = AnyPublicKey(pub)
        s = {any_pub, any_pub}
        assert len(s) == 1

    def test_repr(self):
        pub = self._ed25519_pub()
        r = repr(AnyPublicKey(pub))
        assert "ED25519" in r

    def test_to_crypto_bytes_returns_bytes(self):
        pub = self._ed25519_pub()
        any_pub = AnyPublicKey(pub)
        crypto_bytes = any_pub.to_crypto_bytes()
        assert isinstance(crypto_bytes, bytes)
        assert len(crypto_bytes) > 0

    def test_verify_ed25519_valid(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        any_pub = AnyPublicKey(pub)
        msg = b"test message"
        sig = priv.sign(msg)
        any_sig = AnySignature(sig)
        assert any_pub.verify(msg, any_sig)

    def test_verify_ed25519_wrong_message(self):
        priv = Ed25519PrivateKey.generate()
        any_pub = AnyPublicKey(priv.public_key())
        sig = priv.sign(b"original")
        any_sig = AnySignature(sig)
        assert not any_pub.verify(b"tampered", any_sig)

    def test_verify_secp256k1_valid(self):
        priv = Secp256k1PrivateKey.generate()
        any_pub = AnyPublicKey(priv.public_key())
        msg = b"secp256k1 test"
        sig = priv.sign(msg)
        any_sig = AnySignature(sig)
        assert any_pub.verify(msg, any_sig)

    def test_bcs_round_trip_ed25519(self):
        original = AnyPublicKey(self._ed25519_pub())
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AnyPublicKey.deserialize(der)
        assert original == restored

    def test_bcs_round_trip_secp256k1(self):
        original = AnyPublicKey(self._secp256k1_pub())
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AnyPublicKey.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# AnySignature
# ---------------------------------------------------------------------------


class TestAnySignature:
    def _ed25519_sig(self) -> Ed25519Signature:
        priv = Ed25519PrivateKey.generate()
        return priv.sign(b"test")

    def _secp256k1_sig(self) -> Secp256k1Signature:
        priv = Secp256k1PrivateKey.generate()
        return priv.sign(b"test")

    def test_wraps_ed25519(self):
        sig = self._ed25519_sig()
        any_sig = AnySignature(sig)
        assert any_sig.variant == AnySignature.ED25519

    def test_wraps_secp256k1(self):
        sig = self._secp256k1_sig()
        any_sig = AnySignature(sig)
        assert any_sig.variant == AnySignature.SECP256K1_ECDSA

    def test_invalid_type_raises(self):
        with pytest.raises(InvalidSignatureError):
            AnySignature("not a signature")  # type: ignore[arg-type]

    def test_equality(self):
        sig = self._ed25519_sig()
        a = AnySignature(sig)
        b = AnySignature(sig)
        assert a == b

    def test_repr(self):
        sig = self._ed25519_sig()
        r = repr(AnySignature(sig))
        assert "ED25519" in r

    def test_bcs_round_trip_ed25519(self):
        original = AnySignature(self._ed25519_sig())
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AnySignature.deserialize(der)
        assert original == restored

    def test_bcs_round_trip_secp256k1(self):
        original = AnySignature(self._secp256k1_sig())
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AnySignature.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# MultiKeyPublicKey
# ---------------------------------------------------------------------------


class TestMultiKeyPublicKey:
    def _ed25519_pub(self) -> Ed25519PublicKey:
        return Ed25519PrivateKey.generate().public_key()

    def _secp256k1_pub(self) -> Secp256k1PublicKey:
        return Secp256k1PrivateKey.generate().public_key()

    def test_construction_with_any_public_keys(self):
        keys = [AnyPublicKey(self._ed25519_pub()), AnyPublicKey(self._ed25519_pub())]
        multi = MultiKeyPublicKey(keys, 2)
        assert multi.threshold == 2
        assert len(multi.keys) == 2

    def test_auto_wraps_bare_keys(self):
        keys = [self._ed25519_pub(), self._ed25519_pub()]
        multi = MultiKeyPublicKey(keys, 1)
        assert all(isinstance(k, AnyPublicKey) for k in multi.keys)

    def test_mixed_key_types(self):
        keys = [self._ed25519_pub(), self._secp256k1_pub()]
        multi = MultiKeyPublicKey(keys, 1)
        assert multi.keys[0].variant == AnyPublicKey.ED25519
        assert multi.keys[1].variant == AnyPublicKey.SECP256K1_ECDSA

    def test_too_few_keys_raises(self):
        with pytest.raises(CryptoError):
            MultiKeyPublicKey([self._ed25519_pub()], 1)

    def test_threshold_too_high_raises(self):
        keys = [self._ed25519_pub(), self._ed25519_pub()]
        with pytest.raises(CryptoError):
            MultiKeyPublicKey(keys, 3)

    def test_threshold_zero_raises(self):
        keys = [self._ed25519_pub(), self._ed25519_pub()]
        with pytest.raises(CryptoError):
            MultiKeyPublicKey(keys, 0)

    def test_to_crypto_bytes(self):
        keys = [self._ed25519_pub(), self._ed25519_pub()]
        multi = MultiKeyPublicKey(keys, 2)
        cb = multi.to_crypto_bytes()
        assert isinstance(cb, bytes)
        assert len(cb) > 0

    def test_equality(self):
        pub = self._ed25519_pub()
        keys = [pub, pub]
        a = MultiKeyPublicKey(keys, 2)
        b = MultiKeyPublicKey(keys, 2)
        assert a == b

    def test_bcs_round_trip(self):
        keys = [self._ed25519_pub(), self._secp256k1_pub()]
        original = MultiKeyPublicKey(keys, 1)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MultiKeyPublicKey.deserialize(der)
        assert original == restored

    def test_verify_with_valid_signatures(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        keys = [priv1.public_key(), priv2.public_key()]
        multi_pub = MultiKeyPublicKey(keys, 2)
        msg = b"verify multi key"
        sig1 = AnySignature(priv1.sign(msg))
        sig2 = AnySignature(priv2.sign(msg))
        multi_sig = MultiKeySignature([(0, sig1), (1, sig2)])
        assert multi_pub.verify(msg, multi_sig)


# ---------------------------------------------------------------------------
# MultiKeySignature
# ---------------------------------------------------------------------------


class TestMultiKeySignature:
    def _ed25519_sig(self, msg=b"test") -> Ed25519Signature:
        return Ed25519PrivateKey.generate().sign(msg)

    def test_construction(self):
        sig = AnySignature(self._ed25519_sig())
        multi = MultiKeySignature([(0, sig)])
        assert len(multi.signatures) == 1

    def test_auto_wraps_bare_signatures(self):
        sig = self._ed25519_sig()  # bare Ed25519Signature
        multi = MultiKeySignature([(0, sig)])
        assert isinstance(multi.signatures[0][1], AnySignature)

    def test_index_too_high_raises(self):
        sig = AnySignature(self._ed25519_sig())
        with pytest.raises(InvalidSignatureError):
            MultiKeySignature([(16, sig)])  # 16 >= MAX_SIGNATURES

    def test_equality(self):
        sig = AnySignature(self._ed25519_sig())
        a = MultiKeySignature([(0, sig)])
        b = MultiKeySignature([(0, sig)])
        assert a == b

    def test_bcs_round_trip(self):
        priv0 = Ed25519PrivateKey.generate()
        priv1 = Ed25519PrivateKey.generate()
        msg = b"multi key bcs"
        sig0 = AnySignature(priv0.sign(msg))
        sig1 = AnySignature(priv1.sign(msg))
        original = MultiKeySignature([(0, sig0), (1, sig1)])
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MultiKeySignature.deserialize(der)
        assert original == restored

    def test_repr(self):
        sig = AnySignature(self._ed25519_sig())
        multi = MultiKeySignature([(0, sig)])
        r = repr(multi)
        assert "MultiKeySignature" in r
