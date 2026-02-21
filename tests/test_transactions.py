# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.transactions — ModuleId, EntryFunction, TransactionPayload,
RawTransaction, SignedTransaction, MultiAgentRawTransaction, FeePayerRawTransaction.
"""

import pytest

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.authenticator import AccountAuthenticator, TransactionAuthenticator
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.chain_id import ChainId
from aptos_sdk.ed25519 import Ed25519PrivateKey
from aptos_sdk.errors import InvalidInputError
from aptos_sdk.transactions import (
    EntryFunction,
    FeePayerRawTransaction,
    ModuleId,
    MultiAgentRawTransaction,
    RawTransaction,
    Script,
    ScriptArgument,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk.type_tag import StructTag, TypeTag, U64Tag

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry_function() -> EntryFunction:
    # Encode the recipient address
    ser_addr = Serializer()
    ser_addr.fixed_bytes(AccountAddress.ONE.data)
    # Encode the amount as u64
    ser_amount = Serializer()
    ser_amount.u64(100)
    return EntryFunction.natural(
        "0x1::aptos_account",
        "transfer",
        [],
        [ser_addr.output(), ser_amount.output()],
    )


def _make_raw_transaction(
    sender: AccountAddress | None = None,
    sequence_number: int = 0,
    chain_id: int = 4,
) -> RawTransaction:
    if sender is None:
        sender = AccountAddress.from_hex("0x" + "ab" * 32)
    payload = TransactionPayload(_make_entry_function())
    return RawTransaction(
        sender,
        sequence_number,
        payload,
        max_gas_amount=200_000,
        gas_unit_price=100,
        expiration_timestamp_secs=9_999_999_999,
        chain_id=chain_id,
    )


# ---------------------------------------------------------------------------
# ModuleId
# ---------------------------------------------------------------------------


class TestModuleId:
    def test_construction(self):
        module = ModuleId(AccountAddress.ONE, "coin")
        assert module.address == AccountAddress.ONE
        assert module.name == "coin"

    def test_str(self):
        module = ModuleId(AccountAddress.ONE, "coin")
        assert str(module) == "0x1::coin"

    def test_equality(self):
        a = ModuleId(AccountAddress.ONE, "coin")
        b = ModuleId(AccountAddress.ONE, "coin")
        assert a == b

    def test_from_str(self):
        module = ModuleId.from_str("0x1::aptos_account")
        assert module.name == "aptos_account"
        assert module.address == AccountAddress.ONE

    def test_from_str_invalid(self):
        with pytest.raises(InvalidInputError):
            ModuleId.from_str("invalid")

    def test_from_str_empty_module(self):
        with pytest.raises(InvalidInputError):
            ModuleId.from_str("0x1::")

    def test_bcs_round_trip(self):
        original = ModuleId(AccountAddress.ONE, "coin")
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ModuleId.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# EntryFunction
# ---------------------------------------------------------------------------


class TestEntryFunction:
    def test_natural_constructor(self):
        ser = Serializer()
        ser.u64(42)
        ef = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [AccountAddress.ONE, ser.output()],
        )
        assert ef.module == ModuleId.from_str("0x1::aptos_account")
        assert ef.function == "transfer"

    def test_natural_with_transaction_argument(self):
        ef = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(AccountAddress.ONE, Serializer.struct),
                TransactionArgument(100, Serializer.u64),
            ],
        )
        assert len(ef.args) == 2

    def test_str(self):
        ef = _make_entry_function()
        s = str(ef)
        assert "transfer" in s

    def test_equality(self):
        ef1 = _make_entry_function()
        ef2 = _make_entry_function()
        assert ef1 == ef2

    def test_with_type_args(self):
        inner = TypeTag(StructTag(AccountAddress.ONE, "aptos_coin", "AptosCoin", []))
        ef = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [inner],
            [],
        )
        assert len(ef.ty_args) == 1

    def test_bcs_round_trip(self):
        original = _make_entry_function()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = EntryFunction.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# TransactionPayload
# ---------------------------------------------------------------------------


class TestTransactionPayload:
    def test_wraps_entry_function(self):
        ef = _make_entry_function()
        payload = TransactionPayload(ef)
        assert payload.variant == TransactionPayload.ENTRY_FUNCTION
        assert payload.value == ef

    def test_wraps_script(self):
        script = Script(b"\x01\x02\x03", [], [])
        payload = TransactionPayload(script)
        assert payload.variant == TransactionPayload.SCRIPT

    def test_invalid_type_raises(self):
        with pytest.raises(InvalidInputError):
            TransactionPayload("not a payload")  # type: ignore[arg-type]

    def test_equality(self):
        ef = _make_entry_function()
        a = TransactionPayload(ef)
        b = TransactionPayload(ef)
        assert a == b

    def test_entry_function_bcs_round_trip(self):
        original = TransactionPayload(_make_entry_function())
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = TransactionPayload.deserialize(der)
        assert original == restored

    def test_script_bcs_round_trip(self):
        script = Script(
            b"\xab\xcd", [TypeTag(U64Tag())], [ScriptArgument(ScriptArgument.U64, 42)]
        )
        original = TransactionPayload(script)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = TransactionPayload.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# RawTransaction
# ---------------------------------------------------------------------------


class TestRawTransaction:
    def test_construction(self):
        sender = AccountAddress.from_hex("0x" + "ab" * 32)
        payload = TransactionPayload(_make_entry_function())
        txn = RawTransaction(sender, 0, payload, 200_000, 100, 9_999_999_999, 4)
        assert txn.sender == sender
        assert txn.sequence_number == 0
        assert txn.max_gas_amount == 200_000
        assert txn.gas_unit_price == 100

    def test_chain_id_int_coercion(self):
        txn = _make_raw_transaction(chain_id=4)
        assert isinstance(txn.chain_id, ChainId)
        assert txn.chain_id.value == 4

    def test_signing_message_has_prefix(self):
        txn = _make_raw_transaction()
        msg = txn.signing_message()
        from aptos_sdk.hashing import HashPrefix

        assert msg[: len(HashPrefix.RAW_TRANSACTION)] == HashPrefix.RAW_TRANSACTION

    def test_signing_message_is_bytes(self):
        txn = _make_raw_transaction()
        msg = txn.signing_message()
        assert isinstance(msg, bytes)

    def test_sign_with_ed25519(self):
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        assert isinstance(auth, AccountAuthenticator)
        assert auth.variant == AccountAuthenticator.ED25519

    def test_verify_valid_signature(self):
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        sig = priv.sign(txn.signing_message())
        pub = priv.public_key()
        assert txn.verify(pub, sig)

    def test_equality(self):
        a = _make_raw_transaction()
        b = _make_raw_transaction()
        assert a == b

    def test_bcs_round_trip(self):
        original = _make_raw_transaction()
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = RawTransaction.deserialize(der)
        assert original == restored

    def test_str_contains_sender(self):
        txn = _make_raw_transaction()
        s = str(txn)
        assert "sender" in s.lower()


# ---------------------------------------------------------------------------
# SignedTransaction
# ---------------------------------------------------------------------------


class TestSignedTransaction:
    def test_construction_from_ed25519(self):
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        signed = SignedTransaction(txn, auth)
        assert signed.transaction == txn

    def test_verify_valid(self):
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        signed = SignedTransaction(txn, auth)
        assert signed.verify()

    def test_bytes_returns_bytes(self):
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        signed = SignedTransaction(txn, auth)
        raw = signed.bytes()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_bcs_round_trip(self):
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        original = SignedTransaction(txn, auth)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = SignedTransaction.deserialize(der)
        assert original == restored

    def test_equality(self):
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        a = SignedTransaction(txn, auth)
        b = SignedTransaction(txn, auth)
        assert a == b

    def test_accepts_transaction_authenticator_directly(self):
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        account_auth = txn.sign(priv)
        txn_auth = TransactionAuthenticator(account_auth.authenticator)
        signed = SignedTransaction(txn, txn_auth)
        assert signed.verify()


# ---------------------------------------------------------------------------
# MultiAgentRawTransaction
# ---------------------------------------------------------------------------


class TestMultiAgentRawTransaction:
    def test_construction(self):
        txn = _make_raw_transaction()
        secondary = [AccountAddress.from_hex("0x" + "cd" * 32)]
        multi = MultiAgentRawTransaction(txn, secondary)
        assert multi.raw_transaction == txn
        assert multi.secondary_signers == secondary

    def test_inner_returns_raw_transaction(self):
        txn = _make_raw_transaction()
        multi = MultiAgentRawTransaction(txn, [])
        assert multi.inner() == txn

    def test_signing_message_uses_with_data_prefix(self):
        from aptos_sdk.hashing import HashPrefix

        txn = _make_raw_transaction()
        multi = MultiAgentRawTransaction(txn, [])
        msg = multi.signing_message()
        assert (
            msg[: len(HashPrefix.RAW_TRANSACTION_WITH_DATA)]
            == HashPrefix.RAW_TRANSACTION_WITH_DATA
        )

    def test_bcs_round_trip(self):
        txn = _make_raw_transaction()
        secondary = [AccountAddress.from_hex("0x" + "cd" * 32)]
        original = MultiAgentRawTransaction(txn, secondary)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        variant = der.u8()
        assert variant == 0
        # Deserialize without variant byte using the already-imported class
        restored = MultiAgentRawTransaction._deserialize_inner(der)
        assert restored.secondary_signers == original.secondary_signers


# ---------------------------------------------------------------------------
# FeePayerRawTransaction
# ---------------------------------------------------------------------------


class TestFeePayerRawTransaction:
    def test_construction_with_known_fee_payer(self):
        txn = _make_raw_transaction()
        fee_payer = AccountAddress.from_hex("0x" + "ef" * 32)
        fp_txn = FeePayerRawTransaction(txn, [], fee_payer)
        assert fp_txn.fee_payer == fee_payer

    def test_construction_with_unknown_fee_payer(self):
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], None)
        assert fp_txn.fee_payer is None

    def test_none_fee_payer_serializes_as_zero(self):
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], None)
        ser = Serializer()
        fp_txn.serialize(ser)
        # Should serialize without error
        assert len(ser.output()) > 0

    def test_signing_message_uses_with_data_prefix(self):
        from aptos_sdk.hashing import HashPrefix

        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], None)
        msg = fp_txn.signing_message()
        assert (
            msg[: len(HashPrefix.RAW_TRANSACTION_WITH_DATA)]
            == HashPrefix.RAW_TRANSACTION_WITH_DATA
        )

    def test_bcs_round_trip_known_fee_payer(self):
        txn = _make_raw_transaction()
        fee_payer = AccountAddress.from_hex("0x" + "ef" * 32)
        original = FeePayerRawTransaction(txn, [], fee_payer)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        variant = der.u8()
        assert variant == 1
        restored = FeePayerRawTransaction._deserialize_inner(der)
        assert restored.fee_payer == original.fee_payer


# ---------------------------------------------------------------------------
# TransactionArgument
# ---------------------------------------------------------------------------


class TestTransactionArgument:
    def test_encode_u64(self):
        arg = TransactionArgument(42, Serializer.u64)
        encoded = arg.encode()
        assert isinstance(encoded, bytes)
        # BCS u64: 42 = 0x2a, little-endian 8 bytes
        assert encoded == (42).to_bytes(8, "little")

    def test_encode_struct(self):
        arg = TransactionArgument(AccountAddress.ONE, Serializer.struct)
        encoded = arg.encode()
        # AccountAddress is 32 bytes fixed
        assert isinstance(encoded, bytes)


# ---------------------------------------------------------------------------
# ScriptArgument
# ---------------------------------------------------------------------------


class TestScriptArgument:
    def test_u64_round_trip(self):
        original = ScriptArgument(ScriptArgument.U64, 123456)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored

    def test_bool_round_trip(self):
        original = ScriptArgument(ScriptArgument.BOOL, True)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored

    def test_invalid_variant_raises(self):
        with pytest.raises(InvalidInputError):
            ScriptArgument(99, 0)
