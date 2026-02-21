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
    Ed25519PublicKey,
    Ed25519Signature,
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
        assert isinstance(auth.public_key, Ed25519PublicKey)
        assert isinstance(auth.signature, Ed25519Signature)

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


# ---------------------------------------------------------------------------
# Display methods (__repr__ / __str__) — covering lines 67, 71, 216, 220, 223,
# 279, 283, 286, 382, 388, 391, 423, 427, 474, 478, 481, 538, 545, 548
# ---------------------------------------------------------------------------


class TestDisplayMethods:
    """Ensure __repr__ and __str__ are exercised for every authenticator class."""

    def test_ed25519_authenticator_repr(self):
        # Lines 67, 71: Ed25519Authenticator.__repr__ delegates to __str__
        auth = _make_ed25519_auth()
        r = repr(auth)
        assert "PublicKey" in r
        assert r == str(auth)

    def test_multi_ed25519_authenticator_str_and_repr(self):
        # Lines 134, 137: MultiEd25519Authenticator.__repr__ / __str__
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        multi_pub = MultiEd25519PublicKey([priv1.public_key(), priv2.public_key()], 2)
        msg = b"display"
        multi_sig = MultiEd25519Signature([(0, priv1.sign(msg)), (1, priv2.sign(msg))])
        auth = MultiEd25519Authenticator(multi_pub, multi_sig)
        s = str(auth)
        assert "PublicKey" in s
        assert repr(auth) == s

    def test_single_key_authenticator_str_and_repr(self):
        # Lines 220, 223: SingleKeyAuthenticator.__repr__ / __str__
        auth = _make_ed25519_single_key_auth()
        s = str(auth)
        assert "PublicKey" in s
        assert repr(auth) == s

    def test_multi_key_authenticator_str_and_repr(self):
        # Lines 283, 286: MultiKeyAuthenticator.__repr__ / __str__
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"mk display"
        keys = [priv1.public_key(), priv2.public_key()]
        multi_pub = MultiKeyPublicKey(keys, 2)
        sig1 = AnySignature(priv1.sign(msg))
        sig2 = AnySignature(priv2.sign(msg))
        multi_sig = MultiKeySignature([(0, sig1), (1, sig2)])
        auth = MultiKeyAuthenticator(multi_pub, multi_sig)
        s = str(auth)
        assert "PublicKey" in s
        assert repr(auth) == s

    def test_account_authenticator_str_and_repr(self):
        # Lines 388, 391: AccountAuthenticator.__repr__ / __str__
        inner = _make_ed25519_auth()
        auth = AccountAuthenticator(inner)
        s = str(auth)
        # AccountAuthenticator.__str__ delegates to the inner authenticator
        assert s == str(inner)
        assert repr(auth) == s

    def test_multi_agent_authenticator_str_and_repr(self):
        # Lines 423, 427: MultiAgentAuthenticator.__repr__ / __str__
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        addr = AccountAddress.from_hex("0x" + "ab" * 32)
        secondary_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = MultiAgentAuthenticator(sender_auth, [(addr, secondary_auth)])
        s = str(auth)
        assert "MultiAgent" in s
        assert "Sender" in s
        assert repr(auth) == s

    def test_fee_payer_authenticator_str_and_repr(self):
        # Lines 474, 478, 481: FeePayerAuthenticator.__repr__ / __str__
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_addr = AccountAddress.ONE
        auth = FeePayerAuthenticator(sender_auth, [], (fee_payer_addr, fee_payer_auth))
        s = str(auth)
        assert "FeePayer" in s
        assert "Sender" in s
        assert repr(auth) == s

    def test_single_sender_authenticator_str_and_repr(self):
        # Lines 478, 481: SingleSenderAuthenticator.__repr__ / __str__
        account_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = SingleSenderAuthenticator(account_auth)
        s = str(auth)
        assert "SingleSender" in s
        assert repr(auth) == s

    def test_transaction_authenticator_str_and_repr(self):
        # Lines 538, 545, 548: TransactionAuthenticator.__repr__ / __str__
        inner = _make_ed25519_auth()
        auth = TransactionAuthenticator(inner)
        s = str(auth)
        # TransactionAuthenticator.__str__ delegates to the inner authenticator
        assert s == str(inner)
        assert repr(auth) == s


# ---------------------------------------------------------------------------
# MultiEd25519Authenticator — full coverage of equality, verify, serialize/
# deserialize (lines 129-131, 146, 151-153, 157-158)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Ed25519Authenticator — equality non-instance path (line 67)
# ---------------------------------------------------------------------------


class TestEd25519AuthenticatorAdditional:
    def test_equality_not_instance_returns_not_implemented(self):
        # Line 67: __eq__ returns NotImplemented for non-matching types
        auth = _make_ed25519_auth()
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# SingleSenderAuthenticator — equality non-instance path (line 474)
# ---------------------------------------------------------------------------


class TestSingleSenderAuthenticatorAdditional:
    def test_equality_not_instance_returns_not_implemented(self):
        # Line 474: __eq__ returns NotImplemented for non-matching types
        account_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = SingleSenderAuthenticator(account_auth)
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented


class TestMultiEd25519Authenticator:
    def _make_auth(self, msg: bytes = b"multi-ed test") -> MultiEd25519Authenticator:
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        multi_pub = MultiEd25519PublicKey([priv1.public_key(), priv2.public_key()], 2)
        multi_sig = MultiEd25519Signature([(0, priv1.sign(msg)), (1, priv2.sign(msg))])
        return MultiEd25519Authenticator(multi_pub, multi_sig)

    def test_construction(self):
        auth = self._make_auth()
        assert isinstance(auth.public_key, MultiEd25519PublicKey)
        assert isinstance(auth.signature, MultiEd25519Signature)

    def test_equality_same(self):
        # Line 129-131: __eq__ for matching instances
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"eq test"
        multi_pub = MultiEd25519PublicKey([priv1.public_key(), priv2.public_key()], 2)
        multi_sig = MultiEd25519Signature([(0, priv1.sign(msg)), (1, priv2.sign(msg))])
        a = MultiEd25519Authenticator(multi_pub, multi_sig)
        b = MultiEd25519Authenticator(multi_pub, multi_sig)
        assert a == b

    def test_equality_not_instance_returns_not_implemented(self):
        # Line 129: __eq__ returns NotImplemented for non-matching types
        auth = self._make_auth()
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented

    def test_verify_valid(self):
        # Line 146: verify() returns True for a valid multi-ed25519 signature
        msg = b"verify multi ed"
        auth = self._make_auth(msg)
        assert auth.verify(msg)

    def test_verify_wrong_message_fails(self):
        # Line 146: verify() returns False for a mismatched message
        auth = self._make_auth(b"original message")
        assert not auth.verify(b"tampered message")

    def test_bcs_round_trip(self):
        # Lines 151-153, 157-158: deserialize / serialize
        original = self._make_auth()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MultiEd25519Authenticator.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# AccountAuthenticator — equality non-instance path and remaining deser variants
# (lines 382, MultiEd25519 deser path lines 423 context; MULTI_KEY deser path)
# ---------------------------------------------------------------------------


class TestAccountAuthenticatorAdditional:
    def test_equality_not_instance_returns_not_implemented(self):
        # Line 382: __eq__ returns NotImplemented for non-matching types
        auth = AccountAuthenticator(_make_ed25519_auth())
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented

    def test_bcs_round_trip_multi_ed25519(self):
        # Exercises the MULTI_ED25519 deserialization branch (lines 422-423)
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"account auth multi ed"
        multi_pub = MultiEd25519PublicKey([priv1.public_key(), priv2.public_key()], 2)
        multi_sig = MultiEd25519Signature([(0, priv1.sign(msg)), (1, priv2.sign(msg))])
        inner = MultiEd25519Authenticator(multi_pub, multi_sig)
        original = AccountAuthenticator(inner)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AccountAuthenticator.deserialize(der)
        assert original == restored
        assert restored.variant == AccountAuthenticator.MULTI_ED25519

    def test_bcs_round_trip_multi_key(self):
        # Exercises the MULTI_KEY deserialization branch
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"account auth multi key"
        keys = [priv1.public_key(), priv2.public_key()]
        multi_pub = MultiKeyPublicKey(keys, 2)
        sig1 = AnySignature(priv1.sign(msg))
        sig2 = AnySignature(priv2.sign(msg))
        multi_sig = MultiKeySignature([(0, sig1), (1, sig2)])
        inner = MultiKeyAuthenticator(multi_pub, multi_sig)
        original = AccountAuthenticator(inner)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AccountAuthenticator.deserialize(der)
        assert original == restored
        assert restored.variant == AccountAuthenticator.MULTI_KEY


# ---------------------------------------------------------------------------
# MultiKeyAuthenticator — equality non-instance path (line 279)
# ---------------------------------------------------------------------------


class TestMultiKeyAuthenticatorAdditional:
    def test_equality_not_instance_returns_not_implemented(self):
        # Line 279: __eq__ returns NotImplemented for non-matching types
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"eq test mk"
        keys = [priv1.public_key(), priv2.public_key()]
        multi_pub = MultiKeyPublicKey(keys, 2)
        sig1 = AnySignature(priv1.sign(msg))
        sig2 = AnySignature(priv2.sign(msg))
        multi_sig = MultiKeySignature([(0, sig1), (1, sig2)])
        auth = MultiKeyAuthenticator(multi_pub, multi_sig)
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# SingleKeyAuthenticator — equality non-instance path (line 216)
# ---------------------------------------------------------------------------


class TestSingleKeyAuthenticatorAdditional:
    def test_equality_not_instance_returns_not_implemented(self):
        # Line 216: __eq__ returns NotImplemented for non-matching types
        auth = _make_ed25519_single_key_auth()
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# MultiAgentAuthenticator — verify failure paths (lines 564-566)
# and equality non-instance path
# ---------------------------------------------------------------------------


class TestMultiAgentAuthenticatorAdditional:
    def test_equality_not_instance_returns_not_implemented(self):
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = MultiAgentAuthenticator(sender_auth, [])
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented

    def test_verify_sender_fails_short_circuits(self):
        # Lines 564-565: verify() returns False immediately when sender fails
        priv = Ed25519PrivateKey.generate()
        msg = b"original"
        sig = priv.sign(msg)
        # Pair the signature with a different key so sender.verify() → False
        wrong_priv = Ed25519PrivateKey.generate()
        bad_inner = Ed25519Authenticator(wrong_priv.public_key(), sig)
        sender_auth = AccountAuthenticator(bad_inner)
        secondary_priv = Ed25519PrivateKey.generate()
        secondary_msg = b"secondary"
        secondary_sig = secondary_priv.sign(secondary_msg)
        secondary_inner = Ed25519Authenticator(
            secondary_priv.public_key(), secondary_sig
        )
        secondary_auth = AccountAuthenticator(secondary_inner)
        secondary_addr = AccountAddress.from_hex("0x" + "bb" * 32)
        auth = MultiAgentAuthenticator(sender_auth, [(secondary_addr, secondary_auth)])
        # sender.verify(msg) is False, so verify() should return False immediately
        assert not auth.verify(msg)

    def test_verify_secondary_fails(self):
        # Line 566: verify() returns False when a secondary signer fails
        priv = Ed25519PrivateKey.generate()
        msg = b"msg to sign"
        sig = priv.sign(msg)
        sender_inner = Ed25519Authenticator(priv.public_key(), sig)
        sender_auth = AccountAuthenticator(sender_inner)
        # Secondary uses a mismatched signature (signed a different message)
        sec_priv = Ed25519PrivateKey.generate()
        wrong_sig = sec_priv.sign(b"different message")
        bad_secondary_inner = Ed25519Authenticator(sec_priv.public_key(), wrong_sig)
        secondary_auth = AccountAuthenticator(bad_secondary_inner)
        secondary_addr = AccountAddress.from_hex("0x" + "cc" * 32)
        auth = MultiAgentAuthenticator(sender_auth, [(secondary_addr, secondary_auth)])
        # sender.verify(msg) is True; secondary.verify(msg) is False
        assert not auth.verify(msg)

    def test_verify_all_valid(self):
        # Lines 564-566: happy path — sender and secondary both verify
        priv = Ed25519PrivateKey.generate()
        msg = b"all valid"
        sig = priv.sign(msg)
        sender_inner = Ed25519Authenticator(priv.public_key(), sig)
        sender_auth = AccountAuthenticator(sender_inner)
        sec_priv = Ed25519PrivateKey.generate()
        sec_sig = sec_priv.sign(msg)
        secondary_inner = Ed25519Authenticator(sec_priv.public_key(), sec_sig)
        secondary_auth = AccountAuthenticator(secondary_inner)
        secondary_addr = AccountAddress.from_hex("0x" + "dd" * 32)
        auth = MultiAgentAuthenticator(sender_auth, [(secondary_addr, secondary_auth)])
        assert auth.verify(msg)


# ---------------------------------------------------------------------------
# FeePayerAuthenticator — secondary_addresses and verify failure paths
# (lines 646, 654, 657, 669, 678-682)
# ---------------------------------------------------------------------------


class TestFeePayerAuthenticatorAdditional:
    def test_equality_not_instance_returns_not_implemented(self):
        # Line 646: __eq__ returns NotImplemented for non-matching types
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_auth = AccountAuthenticator(_make_ed25519_auth())
        auth = FeePayerAuthenticator(
            sender_auth, [], (AccountAddress.ONE, fee_payer_auth)
        )
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented

    def test_secondary_addresses_multiple(self):
        # Line 669: secondary_addresses() with multiple secondaries
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_auth = AccountAuthenticator(_make_ed25519_auth())
        addr1 = AccountAddress.from_hex("0x" + "11" * 32)
        addr2 = AccountAddress.from_hex("0x" + "22" * 32)
        sec_auth1 = AccountAuthenticator(_make_ed25519_auth())
        sec_auth2 = AccountAuthenticator(_make_ed25519_auth())
        auth = FeePayerAuthenticator(
            sender_auth,
            [(addr1, sec_auth1), (addr2, sec_auth2)],
            (AccountAddress.ONE, fee_payer_auth),
        )
        addrs = auth.secondary_addresses()
        assert len(addrs) == 2
        assert addrs[0] == addr1
        assert addrs[1] == addr2

    def test_verify_sender_fails_short_circuits(self):
        # Lines 678-679: verify() returns False immediately when sender fails
        priv = Ed25519PrivateKey.generate()
        msg = b"fee payer msg"
        sig = priv.sign(msg)
        wrong_priv = Ed25519PrivateKey.generate()
        bad_inner = Ed25519Authenticator(wrong_priv.public_key(), sig)
        sender_auth = AccountAuthenticator(bad_inner)
        fp_priv = Ed25519PrivateKey.generate()
        fp_sig = fp_priv.sign(msg)
        fp_inner = Ed25519Authenticator(fp_priv.public_key(), fp_sig)
        fee_payer_auth = AccountAuthenticator(fp_inner)
        auth = FeePayerAuthenticator(
            sender_auth, [], (AccountAddress.ONE, fee_payer_auth)
        )
        assert not auth.verify(msg)

    def test_verify_fee_payer_fails(self):
        # Lines 680-681: verify() returns False when fee payer fails
        priv = Ed25519PrivateKey.generate()
        msg = b"fee payer msg 2"
        sig = priv.sign(msg)
        sender_inner = Ed25519Authenticator(priv.public_key(), sig)
        sender_auth = AccountAuthenticator(sender_inner)
        fp_priv = Ed25519PrivateKey.generate()
        # Fee payer signs a different message so verification fails
        fp_sig = fp_priv.sign(b"wrong message")
        fp_inner = Ed25519Authenticator(fp_priv.public_key(), fp_sig)
        fee_payer_auth = AccountAuthenticator(fp_inner)
        auth = FeePayerAuthenticator(
            sender_auth, [], (AccountAddress.ONE, fee_payer_auth)
        )
        assert not auth.verify(msg)

    def test_verify_secondary_fails(self):
        # Line 682: verify() returns False when a secondary signer fails
        priv = Ed25519PrivateKey.generate()
        msg = b"fee payer msg 3"
        sig = priv.sign(msg)
        sender_inner = Ed25519Authenticator(priv.public_key(), sig)
        sender_auth = AccountAuthenticator(sender_inner)
        fp_priv = Ed25519PrivateKey.generate()
        fp_sig = fp_priv.sign(msg)
        fp_inner = Ed25519Authenticator(fp_priv.public_key(), fp_sig)
        fee_payer_auth = AccountAuthenticator(fp_inner)
        sec_priv = Ed25519PrivateKey.generate()
        # Secondary signs a different message so verification fails
        sec_sig = sec_priv.sign(b"not the same msg")
        sec_inner = Ed25519Authenticator(sec_priv.public_key(), sec_sig)
        secondary_auth = AccountAuthenticator(sec_inner)
        secondary_addr = AccountAddress.from_hex("0x" + "ee" * 32)
        auth = FeePayerAuthenticator(
            sender_auth,
            [(secondary_addr, secondary_auth)],
            (AccountAddress.ONE, fee_payer_auth),
        )
        assert not auth.verify(msg)

    def test_verify_all_valid_with_secondary(self):
        # Lines 678-682: happy path with sender, secondary, and fee payer all verifying
        priv = Ed25519PrivateKey.generate()
        msg = b"all valid fee payer"
        sig = priv.sign(msg)
        sender_inner = Ed25519Authenticator(priv.public_key(), sig)
        sender_auth = AccountAuthenticator(sender_inner)
        fp_priv = Ed25519PrivateKey.generate()
        fp_sig = fp_priv.sign(msg)
        fp_inner = Ed25519Authenticator(fp_priv.public_key(), fp_sig)
        fee_payer_auth = AccountAuthenticator(fp_inner)
        sec_priv = Ed25519PrivateKey.generate()
        sec_sig = sec_priv.sign(msg)
        sec_inner = Ed25519Authenticator(sec_priv.public_key(), sec_sig)
        secondary_auth = AccountAuthenticator(sec_inner)
        secondary_addr = AccountAddress.from_hex("0x" + "aa" * 32)
        auth = FeePayerAuthenticator(
            sender_auth,
            [(secondary_addr, secondary_auth)],
            (AccountAddress.ONE, fee_payer_auth),
        )
        assert auth.verify(msg)

    def test_bcs_round_trip_with_secondary(self):
        # Exercises serialize/deserialize with a secondary signer present
        priv = Ed25519PrivateKey.generate()
        msg = b"fee payer round trip secondary"
        sig = priv.sign(msg)
        sender_inner = Ed25519Authenticator(priv.public_key(), sig)
        sender_auth = AccountAuthenticator(sender_inner)
        fp_priv = Ed25519PrivateKey.generate()
        fp_sig = fp_priv.sign(msg)
        fp_inner = Ed25519Authenticator(fp_priv.public_key(), fp_sig)
        fee_payer_auth = AccountAuthenticator(fp_inner)
        sec_priv = Ed25519PrivateKey.generate()
        sec_sig = sec_priv.sign(msg)
        sec_inner = Ed25519Authenticator(sec_priv.public_key(), sec_sig)
        secondary_auth = AccountAuthenticator(sec_inner)
        secondary_addr = AccountAddress.from_hex("0x" + "55" * 32)
        fee_payer_addr = AccountAddress.from_hex("0x" + "66" * 32)
        original = FeePayerAuthenticator(
            sender_auth,
            [(secondary_addr, secondary_auth)],
            (fee_payer_addr, fee_payer_auth),
        )
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = FeePayerAuthenticator.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# TransactionAuthenticator — BCS round trips for remaining variants
# (lines 811, 817, 820, 829, 850, 852, 854) and equality non-instance path
# ---------------------------------------------------------------------------


class TestTransactionAuthenticatorAdditional:
    def test_equality_not_instance_returns_not_implemented(self):
        # Lines 811: __eq__ returns NotImplemented for non-matching types
        auth = TransactionAuthenticator(_make_ed25519_auth())
        result = auth.__eq__("not an authenticator")
        assert result is NotImplemented

    def test_verify_delegates_to_inner(self):
        # Line 829: verify() delegates to inner authenticator
        priv = Ed25519PrivateKey.generate()
        msg = b"tx auth verify"
        sig = priv.sign(msg)
        inner = Ed25519Authenticator(priv.public_key(), sig)
        auth = TransactionAuthenticator(inner)
        assert auth.verify(msg)

    def test_bcs_round_trip_multi_ed25519(self):
        # Lines 849-850: TransactionAuthenticator deserialization of MULTI_ED25519
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"tx multi ed round trip"
        multi_pub = MultiEd25519PublicKey([priv1.public_key(), priv2.public_key()], 2)
        multi_sig = MultiEd25519Signature([(0, priv1.sign(msg)), (1, priv2.sign(msg))])
        inner = MultiEd25519Authenticator(multi_pub, multi_sig)
        original = TransactionAuthenticator(inner)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = TransactionAuthenticator.deserialize(der)
        assert original == restored
        assert restored.variant == TransactionAuthenticator.MULTI_ED25519

    def test_bcs_round_trip_multi_agent(self):
        # Lines 851-852: TransactionAuthenticator deserialization of MULTI_AGENT
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        addr = AccountAddress.from_hex("0x" + "77" * 32)
        secondary_auth = AccountAuthenticator(_make_ed25519_auth())
        inner = MultiAgentAuthenticator(sender_auth, [(addr, secondary_auth)])
        original = TransactionAuthenticator(inner)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = TransactionAuthenticator.deserialize(der)
        assert original == restored
        assert restored.variant == TransactionAuthenticator.MULTI_AGENT

    def test_bcs_round_trip_fee_payer(self):
        # Lines 853-854: TransactionAuthenticator deserialization of FEE_PAYER
        sender_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_auth = AccountAuthenticator(_make_ed25519_auth())
        fee_payer_addr = AccountAddress.from_hex("0x" + "88" * 32)
        inner = FeePayerAuthenticator(sender_auth, [], (fee_payer_addr, fee_payer_auth))
        original = TransactionAuthenticator(inner)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = TransactionAuthenticator.deserialize(der)
        assert original == restored
        assert restored.variant == TransactionAuthenticator.FEE_PAYER
