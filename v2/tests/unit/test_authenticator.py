"""Unit tests for transaction authenticator types."""

import pytest

from aptos_sdk_v2.bcs import Deserializer, Serializer
from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey
from aptos_sdk_v2.crypto.secp256k1 import Secp256k1PrivateKey
from aptos_sdk_v2.crypto.single_key import AnyPublicKey, AnySignature
from aptos_sdk_v2.errors import BcsDeserializationError
from aptos_sdk_v2.transactions.authenticator import (
    AccountAuthenticator,
    Authenticator,
    Ed25519Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
    SingleKeyAuthenticator,
    SingleSenderAuthenticator,
)
from aptos_sdk_v2.types.account_address import AccountAddress


def _make_ed25519_auth():
    key = Ed25519PrivateKey.generate()
    sig = key.sign(b"test")
    return Ed25519Authenticator(key.public_key(), sig)


def _make_single_key_auth():
    key = Secp256k1PrivateKey.generate()
    pub = AnyPublicKey(key.public_key())
    sig = AnySignature(key.sign(b"test"))
    return SingleKeyAuthenticator(pub, sig)


class TestEd25519Authenticator:
    def test_serialize_round_trip(self):
        auth = _make_ed25519_auth()
        ser = Serializer()
        auth.serialize(ser)
        result = Ed25519Authenticator.deserialize(Deserializer(ser.output()))
        assert auth == result

    def test_eq_same(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"data")
        a = Ed25519Authenticator(key.public_key(), sig)
        b = Ed25519Authenticator(key.public_key(), sig)
        assert a == b

    def test_ne_wrong_type(self):
        auth = _make_ed25519_auth()
        assert auth != "not an auth"

    def test_verify(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"data")
        auth = Ed25519Authenticator(key.public_key(), sig)
        assert auth.verify(b"data")
        assert not auth.verify(b"wrong")


class TestSingleKeyAuthenticator:
    def test_serialize_round_trip(self):
        auth = _make_single_key_auth()
        ser = Serializer()
        auth.serialize(ser)
        result = SingleKeyAuthenticator.deserialize(Deserializer(ser.output()))
        assert auth == result

    def test_wraps_raw_keys(self):
        key = Secp256k1PrivateKey.generate()
        auth = SingleKeyAuthenticator(key.public_key(), key.sign(b"data"))
        assert isinstance(auth.public_key, AnyPublicKey)
        assert isinstance(auth.signature, AnySignature)

    def test_eq_same(self):
        key = Secp256k1PrivateKey.generate()
        pub = AnyPublicKey(key.public_key())
        sig = AnySignature(key.sign(b"d"))
        a = SingleKeyAuthenticator(pub, sig)
        b = SingleKeyAuthenticator(pub, sig)
        assert a == b

    def test_ne_wrong_type(self):
        assert _make_single_key_auth() != 42

    def test_verify(self):
        key = Secp256k1PrivateKey.generate()
        sig = key.sign(b"msg")
        auth = SingleKeyAuthenticator(key.public_key(), sig)
        assert auth.verify(b"msg")


class TestSingleSenderAuthenticator:
    def test_serialize_round_trip(self):
        inner = AccountAuthenticator(_make_ed25519_auth())
        auth = SingleSenderAuthenticator(inner)
        ser = Serializer()
        auth.serialize(ser)
        result = SingleSenderAuthenticator.deserialize(Deserializer(ser.output()))
        assert auth == result

    def test_eq(self):
        inner = AccountAuthenticator(_make_ed25519_auth())
        a = SingleSenderAuthenticator(inner)
        b = SingleSenderAuthenticator(inner)
        assert a == b

    def test_ne_wrong_type(self):
        inner = AccountAuthenticator(_make_ed25519_auth())
        assert SingleSenderAuthenticator(inner) != "x"

    def test_verify(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"data")
        ed_auth = Ed25519Authenticator(key.public_key(), sig)
        auth = SingleSenderAuthenticator(AccountAuthenticator(ed_auth))
        assert auth.verify(b"data")


class TestMultiAgentAuthenticator:
    def test_serialize_round_trip(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        addr = AccountAddress.from_str_relaxed("0xBEEF")
        secondary = AccountAuthenticator(_make_ed25519_auth())
        auth = MultiAgentAuthenticator(sender, [(addr, secondary)])
        ser = Serializer()
        auth.serialize(ser)
        result = MultiAgentAuthenticator.deserialize(Deserializer(ser.output()))
        assert auth == result

    def test_secondary_addresses(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        addr = AccountAddress.from_str_relaxed("0xABCD")
        auth = MultiAgentAuthenticator(sender, [(addr, AccountAuthenticator(_make_ed25519_auth()))])
        assert auth.secondary_addresses() == [addr]

    def test_eq(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        a = MultiAgentAuthenticator(sender, [])
        b = MultiAgentAuthenticator(sender, [])
        assert a == b

    def test_ne_wrong_type(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        assert MultiAgentAuthenticator(sender, []) != 42

    def test_verify_with_valid_secondary(self):
        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        data = b"verify_me"
        sender_auth = AccountAuthenticator(
            Ed25519Authenticator(key1.public_key(), key1.sign(data))
        )
        secondary_auth = AccountAuthenticator(
            Ed25519Authenticator(key2.public_key(), key2.sign(data))
        )
        addr = AccountAddress.from_str_relaxed("0xBEEF")
        auth = MultiAgentAuthenticator(sender_auth, [(addr, secondary_auth)])
        assert auth.verify(data)

    def test_verify_sender_fails(self):
        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        sender_auth = AccountAuthenticator(
            Ed25519Authenticator(key1.public_key(), key1.sign(b"wrong"))
        )
        secondary_auth = AccountAuthenticator(
            Ed25519Authenticator(key2.public_key(), key2.sign(b"data"))
        )
        addr = AccountAddress.from_str_relaxed("0xBEEF")
        auth = MultiAgentAuthenticator(sender_auth, [(addr, secondary_auth)])
        assert not auth.verify(b"data")


class TestFeePayerAuthenticator:
    def test_serialize_round_trip(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        fee_addr = AccountAddress.from_str_relaxed("0xFEE")
        fee_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = FeePayerAuthenticator(sender, [], (fee_addr, fee_auth))
        ser = Serializer()
        auth.serialize(ser)
        result = FeePayerAuthenticator.deserialize(Deserializer(ser.output()))
        assert auth == result

    def test_fee_payer_address(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        fee_addr = AccountAddress.from_str_relaxed("0xFEE")
        fee_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = FeePayerAuthenticator(sender, [], (fee_addr, fee_auth))
        assert auth.fee_payer_address() == fee_addr

    def test_secondary_addresses(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        sec_addr = AccountAddress.from_str_relaxed("0x111")
        sec_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_addr = AccountAddress.from_str_relaxed("0xFEE")
        fee_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = FeePayerAuthenticator(sender, [(sec_addr, sec_auth)], (fee_addr, fee_auth))
        assert auth.secondary_addresses() == [sec_addr]

    def test_eq(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        fee = (AccountAddress.from_str_relaxed("0xF"), AccountAuthenticator(_make_ed25519_auth()))
        a = FeePayerAuthenticator(sender, [], fee)
        b = FeePayerAuthenticator(sender, [], fee)
        assert a == b

    def test_ne_wrong_type(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        fee = (AccountAddress.from_str_relaxed("0xF"), AccountAuthenticator(_make_ed25519_auth()))
        assert FeePayerAuthenticator(sender, [], fee) != "x"

    def test_verify_all_pass(self):
        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        key3 = Ed25519PrivateKey.generate()
        data = b"fee_payer_data"
        sender_auth = AccountAuthenticator(
            Ed25519Authenticator(key1.public_key(), key1.sign(data))
        )
        sec_auth = AccountAuthenticator(
            Ed25519Authenticator(key2.public_key(), key2.sign(data))
        )
        sec_addr = AccountAddress.from_str_relaxed("0x111")
        fee_auth = AccountAuthenticator(
            Ed25519Authenticator(key3.public_key(), key3.sign(data))
        )
        fee_addr = AccountAddress.from_str_relaxed("0xFEE")
        auth = FeePayerAuthenticator(sender_auth, [(sec_addr, sec_auth)], (fee_addr, fee_auth))
        assert auth.verify(data)

    def test_verify_fee_payer_fails(self):
        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        data = b"fee_data"
        sender_auth = AccountAuthenticator(
            Ed25519Authenticator(key1.public_key(), key1.sign(data))
        )
        fee_auth = AccountAuthenticator(
            Ed25519Authenticator(key2.public_key(), key2.sign(b"wrong"))
        )
        fee_addr = AccountAddress.from_str_relaxed("0xFEE")
        auth = FeePayerAuthenticator(sender_auth, [], (fee_addr, fee_auth))
        assert not auth.verify(data)

    def test_verify_sender_fails(self):
        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        data = b"fee_data"
        sender_auth = AccountAuthenticator(
            Ed25519Authenticator(key1.public_key(), key1.sign(b"wrong"))
        )
        fee_auth = AccountAuthenticator(
            Ed25519Authenticator(key2.public_key(), key2.sign(data))
        )
        fee_addr = AccountAddress.from_str_relaxed("0xFEE")
        auth = FeePayerAuthenticator(sender_auth, [], (fee_addr, fee_auth))
        assert not auth.verify(data)


class TestAccountAuthenticator:
    def test_ed25519_variant(self):
        auth = AccountAuthenticator(_make_ed25519_auth())
        assert auth.variant == AccountAuthenticator.ED25519

    def test_single_key_variant(self):
        auth = AccountAuthenticator(_make_single_key_auth())
        assert auth.variant == AccountAuthenticator.SINGLE_KEY

    def test_invalid_type_raises(self):
        with pytest.raises(TypeError, match="Invalid"):
            AccountAuthenticator("bad")  # type: ignore[arg-type]

    def test_serialize_round_trip_ed25519(self):
        orig = AccountAuthenticator(_make_ed25519_auth())
        ser = Serializer()
        orig.serialize(ser)
        result = AccountAuthenticator.deserialize(Deserializer(ser.output()))
        assert orig == result

    def test_serialize_round_trip_single_key(self):
        orig = AccountAuthenticator(_make_single_key_auth())
        ser = Serializer()
        orig.serialize(ser)
        result = AccountAuthenticator.deserialize(Deserializer(ser.output()))
        assert orig == result

    def test_eq_same(self):
        inner = _make_ed25519_auth()
        a = AccountAuthenticator(inner)
        b = AccountAuthenticator(inner)
        assert a == b

    def test_ne_wrong_type(self):
        assert AccountAuthenticator(_make_ed25519_auth()) != 42

    def test_unknown_variant_raises(self):
        ser = Serializer()
        ser.uleb128(99)
        with pytest.raises(BcsDeserializationError):
            AccountAuthenticator.deserialize(Deserializer(ser.output()))


class TestAuthenticator:
    def test_ed25519_variant(self):
        auth = Authenticator(_make_ed25519_auth())
        assert auth.variant == Authenticator.ED25519

    def test_multi_agent_variant(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        ma = MultiAgentAuthenticator(sender, [])
        auth = Authenticator(ma)
        assert auth.variant == Authenticator.MULTI_AGENT

    def test_fee_payer_variant(self):
        sender = AccountAuthenticator(_make_ed25519_auth())
        fee = (AccountAddress.from_str_relaxed("0xF"), AccountAuthenticator(_make_ed25519_auth()))
        fp = FeePayerAuthenticator(sender, [], fee)
        auth = Authenticator(fp)
        assert auth.variant == Authenticator.FEE_PAYER

    def test_single_sender_variant(self):
        inner = SingleSenderAuthenticator(AccountAuthenticator(_make_ed25519_auth()))
        auth = Authenticator(inner)
        assert auth.variant == Authenticator.SINGLE_SENDER

    def test_invalid_type_raises(self):
        with pytest.raises(TypeError):
            Authenticator("bad")  # type: ignore[arg-type]

    def test_serialize_round_trip_all_variants(self):
        # Ed25519
        orig = Authenticator(_make_ed25519_auth())
        ser = Serializer()
        orig.serialize(ser)
        result = Authenticator.deserialize(Deserializer(ser.output()))
        assert orig == result

        # MultiAgent
        sender = AccountAuthenticator(_make_ed25519_auth())
        orig = Authenticator(MultiAgentAuthenticator(sender, []))
        ser = Serializer()
        orig.serialize(ser)
        result = Authenticator.deserialize(Deserializer(ser.output()))
        assert orig == result

        # FeePayer
        fee = (AccountAddress.from_str_relaxed("0xF"), AccountAuthenticator(_make_ed25519_auth()))
        orig = Authenticator(FeePayerAuthenticator(sender, [], fee))
        ser = Serializer()
        orig.serialize(ser)
        result = Authenticator.deserialize(Deserializer(ser.output()))
        assert orig == result

        # SingleSender
        orig = Authenticator(SingleSenderAuthenticator(AccountAuthenticator(_make_ed25519_auth())))
        ser = Serializer()
        orig.serialize(ser)
        result = Authenticator.deserialize(Deserializer(ser.output()))
        assert orig == result

    def test_eq_ne(self):
        a = Authenticator(_make_ed25519_auth())
        b = Authenticator(_make_ed25519_auth())
        assert a != b  # different keys
        assert a != "x"

    def test_unknown_variant_raises(self):
        ser = Serializer()
        ser.uleb128(99)
        with pytest.raises(BcsDeserializationError):
            Authenticator.deserialize(Deserializer(ser.output()))
