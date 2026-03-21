"""Unit tests for AuthenticationKey derivation."""

from aptos_sdk_v2.crypto.authentication_key import AuthenticationKey
from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey
from aptos_sdk_v2.crypto.secp256k1 import Secp256k1PrivateKey
from aptos_sdk_v2.crypto.single_key import AnyPublicKey
from aptos_sdk_v2.types.account_address import AccountAddress


class TestFromPublicKey:
    def test_ed25519(self):
        key = Ed25519PrivateKey.generate()
        auth_key = AuthenticationKey.from_public_key(key.public_key())
        addr = auth_key.account_address()
        assert isinstance(addr, AccountAddress)
        assert len(addr.address) == 32

    def test_any_public_key_secp256k1(self):
        key = Secp256k1PrivateKey.generate()
        any_pub = AnyPublicKey(key.public_key())
        auth_key = AuthenticationKey.from_public_key(any_pub)
        addr = auth_key.account_address()
        assert isinstance(addr, AccountAddress)

    def test_hex(self):
        key = Ed25519PrivateKey.generate()
        auth_key = AuthenticationKey.from_public_key(key.public_key())
        h = auth_key.hex()
        assert h.startswith("0x")
        assert len(h) == 66  # 0x + 64 hex chars

    def test_deterministic(self):
        key = Ed25519PrivateKey.from_str(
            "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        a = AuthenticationKey.from_public_key(key.public_key())
        b = AuthenticationKey.from_public_key(key.public_key())
        assert a.account_address() == b.account_address()

    def test_unsupported_key_type_raises(self):
        import pytest

        from aptos_sdk_v2.crypto.keys import PublicKey

        class FakePublicKey(PublicKey):
            def to_crypto_bytes(self) -> bytes:
                return b"\x00" * 32

            def verify(self, data, signature):
                return False

            def serialize(self, serializer):
                pass

            @staticmethod
            def deserialize(deserializer):
                pass

        with pytest.raises(ValueError, match="Unsupported"):
            AuthenticationKey.from_public_key(FakePublicKey())
