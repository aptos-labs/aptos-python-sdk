# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.authenticator — Ed25519Authenticator, MultiEd25519Authenticator,
SingleKeyAuthenticator, MultiKeyAuthenticator, AccountAuthenticator,
TransactionAuthenticator, SingleSenderAuthenticator, MultiAgentAuthenticator,
FeePayerAuthenticator.
"""

import pytest

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.authenticator import (
    AccountAuthenticator,
    Authenticator,
    Ed25519Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
    MultiEd25519Authenticator,
    MultiKeyAuthenticator,
    SingleKeyAuthenticator,
    SingleSenderAuthenticator,
    TransactionAuthenticator,
)
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.crypto_wrapper import (
    AnyPublicKey,
    AnySignature,
    MultiKeyPublicKey,
    MultiKeySignature,
)
from aptos_sdk.ed25519 import (
    Ed25519PrivateKey,
    MultiEd25519PublicKey,
    MultiEd25519Signature,
)
from aptos_sdk.errors import InvalidInputError
from aptos_sdk.secp256k1_ecdsa import Secp256k1PrivateKey

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ed25519_auth() -> Ed25519Authenticator:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    sig = priv.sign(b"test message")
    return Ed25519Authenticator(pub, sig)


def _make_secp256k1_single_key_auth() -> SingleKeyAuthenticator:
    priv = Secp256k1PrivateKey.generate()
    pub = priv.public_key()
    sig = priv.sign(b"test message")
    return SingleKeyAuthenticator(pub, sig)


def _make_ed25519_single_key_auth() -> SingleKeyAuthenticator:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    sig = priv.sign(b"test message")
    return SingleKeyAuthenticator(pub, sig)


# ---------------------------------------------------------------------------
# Ed25519Authenticator
# ---------------------------------------------------------------------------


class TestEd25519Authenticator:
    def test_construction(self):
        auth = _make_ed25519_auth()
        assert auth.public_key is not None
        assert auth.signature is not None

    def test_verify_valid(self):
        priv = Ed25519PrivateKey.generate()
        msg = b"verify this"
        sig = priv.sign(msg)
        auth = Ed25519Authenticator(priv.public_key(), sig)
        assert auth.verify(msg)

    def test_verify_wrong_message_fails(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"original")
        auth = Ed25519Authenticator(priv.public_key(), sig)
        assert not auth.verify(b"tampered")

    def test_equality(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"test")
        a = Ed25519Authenticator(priv.public_key(), sig)
        b = Ed25519Authenticator(priv.public_key(), sig)
        assert a == b

    def test_str(self):
        auth = _make_ed25519_auth()
        s = str(auth)
        assert "PublicKey" in s

    def test_bcs_round_trip(self):
        original = _make_ed25519_auth()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Ed25519Authenticator.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# SingleKeyAuthenticator
# ---------------------------------------------------------------------------


class TestSingleKeyAuthenticator:
    def test_construction_with_ed25519(self):
        auth = _make_ed25519_single_key_auth()
        assert isinstance(auth.public_key, AnyPublicKey)
        assert auth.public_key.variant == AnyPublicKey.ED25519

    def test_construction_with_secp256k1(self):
        auth = _make_secp256k1_single_key_auth()
        assert isinstance(auth.public_key, AnyPublicKey)
        assert auth.public_key.variant == AnyPublicKey.SECP256K1_ECDSA

    def test_auto_wraps_bare_key(self):
        priv = Ed25519PrivateKey.generate()
        bare_pub = priv.public_key()
        sig = priv.sign(b"test")
        auth = SingleKeyAuthenticator(bare_pub, sig)
        assert isinstance(auth.public_key, AnyPublicKey)

    def test_auto_wraps_bare_signature(self):
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"test")
        auth = SingleKeyAuthenticator(priv.public_key(), sig)
        assert isinstance(auth.signature, AnySignature)

    def test_verify_ed25519(self):
        priv = Ed25519PrivateKey.generate()
        msg = b"verify single key"
        sig = priv.sign(msg)
        auth = SingleKeyAuthenticator(priv.public_key(), sig)
        assert auth.verify(msg)

    def test_verify_secp256k1(self):
        priv = Secp256k1PrivateKey.generate()
        msg = b"verify secp256k1"
        sig = priv.sign(msg)
        auth = SingleKeyAuthenticator(priv.public_key(), sig)
        assert auth.verify(msg)

    def test_bcs_round_trip_ed25519(self):
        original = _make_ed25519_single_key_auth()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = SingleKeyAuthenticator.deserialize(der)
        assert original == restored

    def test_bcs_round_trip_secp256k1(self):
        original = _make_secp256k1_single_key_auth()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = SingleKeyAuthenticator.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# MultiKeyAuthenticator
# ---------------------------------------------------------------------------


class TestMultiKeyAuthenticator:
    def test_construction(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"multi key"
        keys = [priv1.public_key(), priv2.public_key()]
        multi_pub = MultiKeyPublicKey(keys, 2)
        sig1 = AnySignature(priv1.sign(msg))
        sig2 = AnySignature(priv2.sign(msg))
        multi_sig = MultiKeySignature([(0, sig1), (1, sig2)])
        auth = MultiKeyAuthenticator(multi_pub, multi_sig)
        assert auth.public_key == multi_pub

    def test_verify_valid(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"multi key verify"
        keys = [priv1.public_key(), priv2.public_key()]
        multi_pub = MultiKeyPublicKey(keys, 2)
        sig1 = AnySignature(priv1.sign(msg))
        sig2 = AnySignature(priv2.sign(msg))
        multi_sig = MultiKeySignature([(0, sig1), (1, sig2)])
        auth = MultiKeyAuthenticator(multi_pub, multi_sig)
        assert auth.verify(msg)

    def test_bcs_round_trip(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"round trip"
        keys = [priv1.public_key(), priv2.public_key()]
        multi_pub = MultiKeyPublicKey(keys, 2)
        sig1 = AnySignature(priv1.sign(msg))
        sig2 = AnySignature(priv2.sign(msg))
        multi_sig = MultiKeySignature([(0, sig1), (1, sig2)])
        original = MultiKeyAuthenticator(multi_pub, multi_sig)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MultiKeyAuthenticator.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# AccountAuthenticator
# ---------------------------------------------------------------------------


class TestAccountAuthenticator:
    def test_ed25519_variant(self):
        inner = _make_ed25519_auth()
        auth = AccountAuthenticator(inner)
        assert auth.variant == AccountAuthenticator.ED25519

    def test_multi_ed25519_variant(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        multi_pub = MultiEd25519PublicKey([priv1.public_key(), priv2.public_key()], 2)
        msg = b"multi"
        multi_sig = MultiEd25519Signature([(0, priv1.sign(msg)), (1, priv2.sign(msg))])
        inner = MultiEd25519Authenticator(multi_pub, multi_sig)
        auth = AccountAuthenticator(inner)
        assert auth.variant == AccountAuthenticator.MULTI_ED25519

    def test_single_key_variant(self):
        inner = _make_ed25519_single_key_auth()
        auth = AccountAuthenticator(inner)
        assert auth.variant == AccountAuthenticator.SINGLE_KEY

    def test_multi_key_variant(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"multi key"
        keys = [priv1.public_key(), priv2.public_key()]
        multi_pub = MultiKeyPublicKey(keys, 2)
        sig1 = AnySignature(priv1.sign(msg))
        sig2 = AnySignature(priv2.sign(msg))
        multi_sig = MultiKeySignature([(0, sig1), (1, sig2)])
        inner = MultiKeyAuthenticator(multi_pub, multi_sig)
        auth = AccountAuthenticator(inner)
        assert auth.variant == AccountAuthenticator.MULTI_KEY

    def test_invalid_inner_raises(self):
        with pytest.raises(InvalidInputError):
            AccountAuthenticator("not valid")  # type: ignore[arg-type]

    def test_verify_delegates_to_inner(self):
        priv = Ed25519PrivateKey.generate()
        msg = b"delegate verify"
        sig = priv.sign(msg)
        inner = Ed25519Authenticator(priv.public_key(), sig)
        auth = AccountAuthenticator(inner)
        assert auth.verify(msg)

    def test_bcs_round_trip_ed25519(self):
        original = AccountAuthenticator(_make_ed25519_auth())
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AccountAuthenticator.deserialize(der)
        assert original == restored

    def test_bcs_round_trip_single_key(self):
        original = AccountAuthenticator(_make_ed25519_single_key_auth())
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AccountAuthenticator.deserialize(der)
        assert original == restored

    def test_unknown_variant_raises(self):
        ser = Serializer()
        ser.variant_index(99)
        der = Deserializer(ser.output())
        with pytest.raises(InvalidInputError):
            AccountAuthenticator.deserialize(der)


# ---------------------------------------------------------------------------
# SingleSenderAuthenticator
# ---------------------------------------------------------------------------


class TestSingleSenderAuthenticator:
    def test_construction(self):
        account_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = SingleSenderAuthenticator(account_auth)
        assert auth.sender == account_auth

    def test_verify(self):
        priv = Ed25519PrivateKey.generate()
        msg = b"single sender"
        sig = priv.sign(msg)
        ed_auth = Ed25519Authenticator(priv.public_key(), sig)
        account_auth = AccountAuthenticator(ed_auth)
        single = SingleSenderAuthenticator(account_auth)
        assert single.verify(msg)

    def test_bcs_round_trip(self):
        account_auth = AccountAuthenticator(_make_ed25519_auth())
        original = SingleSenderAuthenticator(account_auth)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = SingleSenderAuthenticator.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# TransactionAuthenticator
# ---------------------------------------------------------------------------


class TestTransactionAuthenticator:
    def test_ed25519_variant(self):
        inner = _make_ed25519_auth()
        auth = TransactionAuthenticator(inner)
        assert auth.variant == TransactionAuthenticator.ED25519

    def test_multi_ed25519_variant(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        multi_pub = MultiEd25519PublicKey([priv1.public_key(), priv2.public_key()], 2)
        msg = b"tx multi ed"
        multi_sig = MultiEd25519Signature([(0, priv1.sign(msg)), (1, priv2.sign(msg))])
        inner = MultiEd25519Authenticator(multi_pub, multi_sig)
        auth = TransactionAuthenticator(inner)
        assert auth.variant == TransactionAuthenticator.MULTI_ED25519

    def test_single_sender_variant(self):
        account_auth = AccountAuthenticator(_make_ed25519_single_key_auth())
        inner = SingleSenderAuthenticator(account_auth)
        auth = TransactionAuthenticator(inner)
        assert auth.variant == TransactionAuthenticator.SINGLE_SENDER

    def test_multi_agent_variant(self):
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        inner = MultiAgentAuthenticator(sender_auth, [])
        auth = TransactionAuthenticator(inner)
        assert auth.variant == TransactionAuthenticator.MULTI_AGENT

    def test_fee_payer_variant(self):
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_auth = AccountAuthenticator(_make_ed25519_auth())
        inner = FeePayerAuthenticator(
            sender_auth, [], (AccountAddress.ONE, fee_payer_auth)
        )
        auth = TransactionAuthenticator(inner)
        assert auth.variant == TransactionAuthenticator.FEE_PAYER

    def test_invalid_inner_raises(self):
        with pytest.raises(InvalidInputError):
            TransactionAuthenticator("bad")  # type: ignore[arg-type]

    def test_bcs_round_trip_ed25519(self):
        original = TransactionAuthenticator(_make_ed25519_auth())
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = TransactionAuthenticator.deserialize(der)
        assert original == restored

    def test_bcs_round_trip_single_sender(self):
        account_auth = AccountAuthenticator(_make_ed25519_single_key_auth())
        inner = SingleSenderAuthenticator(account_auth)
        original = TransactionAuthenticator(inner)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = TransactionAuthenticator.deserialize(der)
        assert original == restored

    def test_unknown_variant_raises(self):
        ser = Serializer()
        ser.variant_index(99)
        der = Deserializer(ser.output())
        with pytest.raises(InvalidInputError):
            TransactionAuthenticator.deserialize(der)

    def test_back_compat_alias(self):
        assert Authenticator is TransactionAuthenticator


# ---------------------------------------------------------------------------
# MultiAgentAuthenticator
# ---------------------------------------------------------------------------


class TestMultiAgentAuthenticator:
    def test_construction(self):
        Ed25519PrivateKey.generate()
        Ed25519PrivateKey.generate()
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        secondary_auth = AccountAuthenticator(_make_ed25519_auth())
        secondary_addr = AccountAddress.from_hex("0x" + "cc" * 32)
        auth = MultiAgentAuthenticator(sender_auth, [(secondary_addr, secondary_auth)])
        assert auth.sender == sender_auth
        assert len(auth.secondary_signers) == 1

    def test_secondary_addresses(self):
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        addr = AccountAddress.from_hex("0x" + "cc" * 32)
        secondary_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = MultiAgentAuthenticator(sender_auth, [(addr, secondary_auth)])
        addrs = auth.secondary_addresses()
        assert len(addrs) == 1
        assert addrs[0] == addr

    def test_bcs_round_trip(self):
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        addr = AccountAddress.from_hex("0x" + "cc" * 32)
        secondary_auth = AccountAuthenticator(_make_ed25519_auth())
        original = MultiAgentAuthenticator(sender_auth, [(addr, secondary_auth)])
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MultiAgentAuthenticator.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# FeePayerAuthenticator
# ---------------------------------------------------------------------------


class TestFeePayerAuthenticator:
    def test_construction(self):
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_addr = AccountAddress.from_hex("0x" + "ff" * 32)
        auth = FeePayerAuthenticator(sender_auth, [], (fee_payer_addr, fee_payer_auth))
        assert auth.fee_payer_address() == fee_payer_addr

    def test_fee_payer_address(self):
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_addr = AccountAddress.ONE
        auth = FeePayerAuthenticator(sender_auth, [], (fee_payer_addr, fee_payer_auth))
        assert auth.fee_payer_address() == AccountAddress.ONE

    def test_bcs_round_trip(self):
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_addr = AccountAddress.from_hex("0x" + "ff" * 32)
        original = FeePayerAuthenticator(
            sender_auth, [], (fee_payer_addr, fee_payer_auth)
        )
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = FeePayerAuthenticator.deserialize(der)
        assert original == restored
