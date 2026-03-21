"""Unit tests for Ed25519 cryptography — ported from v1 test vectors."""

import pytest

from aptos_sdk_v2.bcs import Deserializer, Serializer
from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature


class TestPrivateKey:
    def test_from_str_hex(self):
        key = Ed25519PrivateKey.from_str(
            "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        assert key.hex() == "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"

    def test_from_str_aip80(self):
        aip80 = "ed25519-priv-0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        key = Ed25519PrivateKey.from_str(aip80, strict=True)
        assert str(key) == aip80

    def test_aip80_formatting(self):
        key = Ed25519PrivateKey.from_str(
            "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        assert key.aip80().startswith("ed25519-priv-0x")

    def test_from_hex_bytes(self):
        raw = bytes.fromhex(
            "4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        key = Ed25519PrivateKey.from_hex(raw)
        assert key.hex() == "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"


class TestSignAndVerify:
    def test_sign_verify(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        sig = key.sign(b"test_message")
        assert pub.verify(b"test_message", sig)

    def test_wrong_message_fails(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        sig = key.sign(b"test_message")
        assert not pub.verify(b"wrong_message", sig)


class TestSerialization:
    def test_private_key_round_trip(self):
        key = Ed25519PrivateKey.generate()
        ser = Serializer()
        key.serialize(ser)
        result = Ed25519PrivateKey.deserialize(Deserializer(ser.output()))
        assert key == result

    def test_public_key_round_trip(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        ser = Serializer()
        pub.serialize(ser)
        result = Ed25519PublicKey.deserialize(Deserializer(ser.output()))
        assert pub == result

    def test_signature_round_trip(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"another_message")
        ser = Serializer()
        sig.serialize(ser)
        result = Ed25519Signature.deserialize(Deserializer(ser.output()))
        assert sig == result


class TestPublicKeyFromStr:
    def test_from_str(self):
        key = Ed25519PrivateKey.from_str(
            "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        pub = key.public_key()
        pub_str = str(pub)
        restored = Ed25519PublicKey.from_str(pub_str)
        assert pub == restored


class TestEdgeCases:
    def test_private_key_generate(self):
        k = Ed25519PrivateKey.generate()
        assert len(k.hex()) > 0

    def test_private_key_eq(self):
        a = Ed25519PrivateKey.generate()
        b = Ed25519PrivateKey.generate()
        assert a != b
        assert a == a  # noqa: PLR0124

    def test_public_key_eq(self):
        k1 = Ed25519PrivateKey.generate()
        k2 = Ed25519PrivateKey.generate()
        assert k1.public_key() != k2.public_key()
        assert k1.public_key() != "not a key"

    def test_signature_eq(self):
        k = Ed25519PrivateKey.generate()
        s1 = k.sign(b"a")
        s2 = k.sign(b"b")
        assert s1 != s2
        assert s1 != "x"

    def test_signature_data(self):
        k = Ed25519PrivateKey.generate()
        sig = k.sign(b"data")
        assert len(sig.data()) == 64

    def test_public_key_to_crypto_bytes(self):
        k = Ed25519PrivateKey.generate()
        pub = k.public_key()
        assert len(pub.to_crypto_bytes()) == 32

    def test_signature_from_str(self):
        k = Ed25519PrivateKey.generate()
        sig = k.sign(b"data")
        restored = Ed25519Signature.from_str(str(sig))
        assert sig == restored

    def test_private_key_str(self):
        k = Ed25519PrivateKey.generate()
        s = str(k)
        assert s.startswith("ed25519-priv-0x")

    def test_public_key_str(self):
        k = Ed25519PrivateKey.generate()
        s = str(k.public_key())
        assert s.startswith("0x")
        assert len(s) == 66  # 0x + 64 hex

    def test_invalid_private_key_length_from_hex(self):
        import pytest
        from aptos_sdk_v2.errors import InvalidKeyError

        with pytest.raises(InvalidKeyError):
            Ed25519PrivateKey.from_hex(b"\x00" * 31)

    def test_invalid_private_key_length_from_str(self):
        import pytest
        from aptos_sdk_v2.errors import InvalidKeyError

        with pytest.raises(InvalidKeyError):
            Ed25519PrivateKey.from_str("0x" + "aa" * 31)

    def test_invalid_public_key_length(self):
        import pytest
        from aptos_sdk_v2.errors import InvalidKeyError

        with pytest.raises(InvalidKeyError):
            Ed25519PublicKey.from_str("0x" + "aa" * 31)

    def test_private_key_ne_different_type(self):
        k = Ed25519PrivateKey.generate()
        assert k != "not a key"

    def test_private_key_deserialize_bad_length(self):
        import pytest
        from aptos_sdk_v2.errors import InvalidKeyError

        ser = Serializer()
        ser.to_bytes(b"\x00" * 31)
        with pytest.raises(InvalidKeyError):
            Ed25519PrivateKey.deserialize(Deserializer(ser.output()))

    def test_public_key_deserialize_bad_length(self):
        import pytest
        from aptos_sdk_v2.errors import InvalidKeyError

        ser = Serializer()
        ser.to_bytes(b"\x00" * 31)
        with pytest.raises(InvalidKeyError):
            Ed25519PublicKey.deserialize(Deserializer(ser.output()))

    def test_signature_deserialize_bad_length(self):
        from aptos_sdk_v2.errors import InvalidSignatureError

        ser = Serializer()
        ser.to_bytes(b"\x00" * 63)
        with pytest.raises(InvalidSignatureError):
            Ed25519Signature.deserialize(Deserializer(ser.output()))


class TestKeysModule:
    """Tests for keys.py helper functions (format_private_key, parse_hex_input)."""

    def test_format_private_key_already_prefixed(self):
        from aptos_sdk_v2.crypto.keys import PrivateKeyVariant, format_private_key

        key = "ed25519-priv-0xabcd"
        assert format_private_key(key, PrivateKeyVariant.ED25519) == key

    def test_parse_hex_input_strict_non_aip80_raises(self):
        from aptos_sdk_v2.crypto.keys import PrivateKeyVariant, parse_hex_input

        with pytest.raises(ValueError, match="AIP-80"):
            parse_hex_input("0xabcd", PrivateKeyVariant.ED25519, strict=True)

    def test_parse_hex_input_invalid_type_raises(self):
        from aptos_sdk_v2.crypto.keys import PrivateKeyVariant, parse_hex_input

        with pytest.raises(TypeError):
            parse_hex_input(12345, PrivateKeyVariant.ED25519)  # type: ignore[arg-type]
