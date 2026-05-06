"""Unit tests for AnyPublicKey and AnySignature wrappers."""

import pytest

from aptos_sdk_v2.bcs import Deserializer, Serializer
from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey
from aptos_sdk_v2.crypto.secp256k1 import Secp256k1PrivateKey
from aptos_sdk_v2.crypto.single_key import AnyPublicKey, AnyPublicKeyVariant, AnySignature
from aptos_sdk_v2.errors import InvalidKeyError, InvalidSignatureError


class TestAnyPublicKeyEd25519:
    def test_wrap_ed25519(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        any_pub = AnyPublicKey(pub)
        assert any_pub._variant == AnyPublicKeyVariant.ED25519
        assert any_pub.inner == pub

    def test_wrap_already_wrapped(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        any1 = AnyPublicKey(pub)
        any2 = AnyPublicKey(any1)
        assert any2._variant == AnyPublicKeyVariant.ED25519
        assert any2.inner == pub

    def test_eq(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        a = AnyPublicKey(pub)
        b = AnyPublicKey(pub)
        assert a == b

    def test_ne_different_keys(self):
        a = AnyPublicKey(Ed25519PrivateKey.generate().public_key())
        b = AnyPublicKey(Ed25519PrivateKey.generate().public_key())
        assert a != b

    def test_ne_wrong_type(self):
        a = AnyPublicKey(Ed25519PrivateKey.generate().public_key())
        assert a != "not a key"

    def test_str(self):
        key = Ed25519PrivateKey.generate()
        any_pub = AnyPublicKey(key.public_key())
        assert any_pub.__str__().startswith("0x")

    def test_to_crypto_bytes(self):
        key = Ed25519PrivateKey.generate()
        any_pub = AnyPublicKey(key.public_key())
        data = any_pub.to_crypto_bytes()
        assert len(data) > 0

    def test_verify_with_signature(self):
        key = Ed25519PrivateKey.generate()
        pub = AnyPublicKey(key.public_key())
        sig = key.sign(b"test")
        assert pub.verify(b"test", sig)

    def test_verify_with_any_signature(self):
        key = Ed25519PrivateKey.generate()
        pub = AnyPublicKey(key.public_key())
        sig = AnySignature(key.sign(b"test"))
        assert pub.verify(b"test", sig)


class TestAnyPublicKeySecp256k1:
    def test_wrap_secp256k1(self):
        key = Secp256k1PrivateKey.generate()
        pub = key.public_key()
        any_pub = AnyPublicKey(pub)
        assert any_pub._variant == AnyPublicKeyVariant.SECP256K1
        assert any_pub.inner == pub

    def test_verify(self):
        key = Secp256k1PrivateKey.generate()
        pub = AnyPublicKey(key.public_key())
        sig = key.sign(b"test")
        assert pub.verify(b"test", sig)


class TestAnyPublicKeyInvalid:
    def test_unsupported_type_raises(self):
        with pytest.raises(InvalidKeyError, match="Unsupported"):
            AnyPublicKey("not a key")  # type: ignore[arg-type]


class TestAnyPublicKeySerialization:
    def test_ed25519_round_trip(self):
        key = Ed25519PrivateKey.generate()
        orig = AnyPublicKey(key.public_key())
        ser = Serializer()
        orig.serialize(ser)
        result = AnyPublicKey.deserialize(Deserializer(ser.output()))
        assert orig == result

    def test_secp256k1_round_trip(self):
        key = Secp256k1PrivateKey.generate()
        orig = AnyPublicKey(key.public_key())
        ser = Serializer()
        orig.serialize(ser)
        result = AnyPublicKey.deserialize(Deserializer(ser.output()))
        assert orig == result

    def test_unknown_variant_raises(self):
        ser = Serializer()
        ser.uleb128(99)
        with pytest.raises(InvalidKeyError):
            AnyPublicKey.deserialize(Deserializer(ser.output()))


class TestAnySignature:
    def test_wrap_ed25519(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"data")
        any_sig = AnySignature(sig)
        assert any_sig._variant == AnyPublicKeyVariant.ED25519
        assert any_sig.inner == sig

    def test_wrap_secp256k1(self):
        key = Secp256k1PrivateKey.generate()
        sig = key.sign(b"data")
        any_sig = AnySignature(sig)
        assert any_sig._variant == AnyPublicKeyVariant.SECP256K1
        assert any_sig.inner == sig

    def test_wrap_already_wrapped(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"data")
        any1 = AnySignature(sig)
        any2 = AnySignature(any1)
        assert any2.inner == sig

    def test_eq(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"data")
        a = AnySignature(sig)
        b = AnySignature(sig)
        assert a == b

    def test_ne_wrong_type(self):
        key = Ed25519PrivateKey.generate()
        a = AnySignature(key.sign(b"data"))
        assert a != "not a sig"

    def test_data(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"data")
        any_sig = AnySignature(sig)
        assert any_sig.data() == sig.data()

    def test_unsupported_type_raises(self):
        with pytest.raises(InvalidSignatureError, match="Unsupported"):
            AnySignature("bad")  # type: ignore[arg-type]

    def test_round_trip(self):
        key = Ed25519PrivateKey.generate()
        orig = AnySignature(key.sign(b"data"))
        ser = Serializer()
        orig.serialize(ser)
        result = AnySignature.deserialize(Deserializer(ser.output()))
        assert orig == result

    def test_unknown_variant_raises(self):
        ser = Serializer()
        ser.uleb128(99)
        with pytest.raises(InvalidSignatureError):
            AnySignature.deserialize(Deserializer(ser.output()))
