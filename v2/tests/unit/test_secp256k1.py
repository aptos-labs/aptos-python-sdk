"""Unit tests for Secp256k1 cryptography — ported from v1 test vectors."""

from aptos_sdk_v2.bcs import Deserializer, Serializer
from aptos_sdk_v2.crypto.secp256k1 import (
    Secp256k1PrivateKey,
    Secp256k1PublicKey,
    Secp256k1Signature,
)


class TestPrivateKey:
    def test_from_str_hex(self):
        key = Secp256k1PrivateKey.from_str(
            "0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        )
        assert key.hex() == "0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"

    def test_from_str_aip80(self):
        aip80 = "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        key = Secp256k1PrivateKey.from_str(aip80, strict=True)
        assert str(key) == aip80

    def test_aip80_formatting(self):
        key = Secp256k1PrivateKey.from_str(
            "0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        )
        assert key.aip80().startswith("secp256k1-priv-0x")


class TestVectors:
    """Test against known vectors from v1."""

    def test_known_vectors(self):
        private_key_hex = (
            "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        )
        public_key_hex = "0x04210c9129e35337ff5d6488f90f18d842cf985f06e0baeff8df4bfb2ac4221863e2631b971a237b5db0aa71188e33250732dd461d56ee623cbe0426a5c2db79ef"
        signature_hex = "0xa539b0973e76fa99b2a864eebd5da950b4dfb399c7afe57ddb34130e454fc9db04dceb2c3d4260b8cc3d3952ab21b5d36c7dc76277fe3747764e6762d12bd9a9"
        data = b"Hello world"

        private_key = Secp256k1PrivateKey.from_str(private_key_hex)
        local_public_key = private_key.public_key()
        local_signature = private_key.sign(data)
        assert local_public_key.verify(data, local_signature)

        original_public_key = Secp256k1PublicKey.from_str(public_key_hex)
        assert original_public_key.verify(data, local_signature)
        assert public_key_hex[2:] == local_public_key.to_crypto_bytes().hex()

        original_signature = Secp256k1Signature.from_str(signature_hex)
        assert original_public_key.verify(data, original_signature)


class TestSignAndVerify:
    def test_sign_verify(self):
        key = Secp256k1PrivateKey.generate()
        pub = key.public_key()
        sig = key.sign(b"test_message")
        assert pub.verify(b"test_message", sig)

    def test_wrong_message_fails(self):
        key = Secp256k1PrivateKey.generate()
        pub = key.public_key()
        sig = key.sign(b"test_message")
        assert not pub.verify(b"wrong_message", sig)


class TestEdgeCases:
    def test_private_key_generate(self):
        k = Secp256k1PrivateKey.generate()
        assert len(k.hex()) > 0

    def test_private_key_eq(self):
        a = Secp256k1PrivateKey.generate()
        b = Secp256k1PrivateKey.generate()
        assert a != b
        assert a != "x"

    def test_public_key_eq(self):
        a = Secp256k1PrivateKey.generate().public_key()
        b = Secp256k1PrivateKey.generate().public_key()
        assert a != b
        assert a != "x"

    def test_public_key_str(self):
        k = Secp256k1PrivateKey.generate()
        pub_str = str(k.public_key())
        assert pub_str.startswith("0x04")

    def test_public_key_to_crypto_bytes(self):
        k = Secp256k1PrivateKey.generate()
        raw = k.public_key().to_crypto_bytes()
        assert len(raw) == 65
        assert raw[0] == 0x04

    def test_public_key_from_str_with_prefix(self):
        k = Secp256k1PrivateKey.generate()
        pub_str = str(k.public_key())
        restored = Secp256k1PublicKey.from_str(pub_str)
        assert k.public_key() == restored

    def test_signature_data(self):
        k = Secp256k1PrivateKey.generate()
        sig = k.sign(b"msg")
        assert len(sig.data()) == 64

    def test_signature_str(self):
        k = Secp256k1PrivateKey.generate()
        sig = k.sign(b"msg")
        assert str(sig).startswith("0x")

    def test_from_hex(self):
        k = Secp256k1PrivateKey.generate()
        raw = bytes.fromhex(k.hex()[2:])
        restored = Secp256k1PrivateKey.from_hex(raw)
        assert k == restored

    def test_private_key_str(self):
        k = Secp256k1PrivateKey.generate()
        s = str(k)
        assert s.startswith("secp256k1-priv-0x")

    def test_invalid_public_key_length(self):
        import pytest

        from aptos_sdk_v2.errors import InvalidKeyError

        with pytest.raises(InvalidKeyError):
            Secp256k1PublicKey(b"\x00" * 63)

    def test_invalid_signature_length(self):
        import pytest

        from aptos_sdk_v2.errors import InvalidSignatureError

        with pytest.raises(InvalidSignatureError):
            Secp256k1Signature.from_str("0x" + "aa" * 63)

    def test_signature_deserialize_bad_length(self):
        import pytest

        from aptos_sdk_v2.errors import InvalidSignatureError

        ser = Serializer()
        ser.to_bytes(b"\x00" * 63)
        with pytest.raises(InvalidSignatureError):
            Secp256k1Signature.deserialize(Deserializer(ser.output()))

    def test_signature_ne_different_type(self):
        k = Secp256k1PrivateKey.generate()
        sig = k.sign(b"msg")
        assert sig != "not a sig"

    def test_invalid_private_key_length_from_str(self):
        import pytest

        from aptos_sdk_v2.errors import InvalidKeyError

        with pytest.raises(InvalidKeyError):
            Secp256k1PrivateKey.from_str("0x" + "aa" * 31)

    def test_invalid_private_key_length_from_hex(self):
        import pytest

        from aptos_sdk_v2.errors import InvalidKeyError

        with pytest.raises(InvalidKeyError):
            Secp256k1PrivateKey.from_hex(b"\x00" * 31)

    def test_invalid_private_key_deserialize_bad_length(self):
        import pytest

        from aptos_sdk_v2.errors import InvalidKeyError

        ser = Serializer()
        ser.to_bytes(b"\x00" * 31)
        with pytest.raises(InvalidKeyError):
            Secp256k1PrivateKey.deserialize(Deserializer(ser.output()))

    def test_verify_with_invalid_signature(self):
        """Verify returns False when given garbage signature data."""
        k = Secp256k1PrivateKey.generate()
        pub = k.public_key()
        bad_sig = Secp256k1Signature(b"\x00" * 64)
        assert not pub.verify(b"msg", bad_sig)

    def test_verify_with_exception_triggering_sig(self):
        """Verify returns False when verify internals raise an exception."""
        from aptos_sdk_v2.crypto.keys import Signature

        k = Secp256k1PrivateKey.generate()
        pub = k.public_key()

        class BrokenSig(Signature):
            def data(self):
                raise RuntimeError("broken")

            def serialize(self, s):
                pass

            @staticmethod
            def deserialize(d):
                pass

        assert not pub.verify(b"msg", BrokenSig())

    def test_low_s_normalization(self):
        """Sign many messages to exercise the low-S normalization branch."""

        k = Secp256k1PrivateKey.generate()
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        for i in range(100):
            sig = k.sign(f"msg_{i}".encode())
            s = int.from_bytes(sig.data()[32:64], "big")
            assert s <= curve_order // 2, "All signatures should have low-S"


class TestDerRoundTrip:
    """Test that signatures can round-trip through DER encoding."""

    def test_round_trip_with_cryptography(self):
        """DER output must be parseable by the cryptography library."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        key = Secp256k1PrivateKey.generate()
        sig = key.sign(b"der_test")
        r = int.from_bytes(sig.data()[:32], "big")
        s = int.from_bytes(sig.data()[32:], "big")
        der = encode_dss_signature(r, s)
        # cryptography should be able to verify the DER signature
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), key.public_key().to_crypto_bytes()
        )
        pub.verify(der, b"der_test", ec.ECDSA(hashes.SHA3_256()))


class TestSerialization:
    def test_private_key_round_trip(self):
        key = Secp256k1PrivateKey.generate()
        ser = Serializer()
        key.serialize(ser)
        result = Secp256k1PrivateKey.deserialize(Deserializer(ser.output()))
        assert key == result

    def test_public_key_round_trip(self):
        key = Secp256k1PrivateKey.generate()
        pub = key.public_key()
        ser = Serializer()
        pub.serialize(ser)
        result = Secp256k1PublicKey.deserialize(Deserializer(ser.output()))
        assert pub == result

    def test_signature_round_trip(self):
        key = Secp256k1PrivateKey.generate()
        sig = key.sign(b"another_message")
        ser = Serializer()
        sig.serialize(ser)
        result = Secp256k1Signature.deserialize(Deserializer(ser.output()))
        assert sig == result
