# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.transactions — ModuleId, EntryFunction, TransactionPayload,
RawTransaction, SignedTransaction, MultiAgentRawTransaction, FeePayerRawTransaction.
"""

import pytest

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.authenticator import (
    AccountAuthenticator,
    Ed25519Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
    TransactionAuthenticator,
)
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.chain_id import ChainId
from aptos_sdk.ed25519 import Ed25519PrivateKey
from aptos_sdk.errors import InvalidInputError
from aptos_sdk.secp256k1_ecdsa import Secp256k1PrivateKey
from aptos_sdk.transactions import (
    EntryFunction,
    FeePayerRawTransaction,
    ModuleId,
    MultiAgentRawTransaction,
    Multisig,
    RawTransaction,
    RawTransactionWithData,
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


# ---------------------------------------------------------------------------
# ModuleId — __repr__ and inequality
# ---------------------------------------------------------------------------


class TestModuleIdRepr:
    def test_repr_equals_str(self):
        # Line 78: __repr__ delegates to __str__
        module = ModuleId(AccountAddress.ONE, "coin")
        assert repr(module) == str(module)
        assert repr(module) == "0x1::coin"

    def test_eq_returns_not_implemented_for_wrong_type(self):
        # Line 71: __eq__ branch for non-ModuleId
        module = ModuleId(AccountAddress.ONE, "coin")
        result = module.__eq__("not_a_module_id")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# ScriptArgument — all remaining variant round-trips and repr
# ---------------------------------------------------------------------------


class TestScriptArgumentAllVariants:
    def test_u8_round_trip(self):
        # Lines 205, 209, 212: __eq__, __str__, __repr__ hit; U8 serialize/deserialize
        original = ScriptArgument(ScriptArgument.U8, 255)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored
        assert original.variant == ScriptArgument.U8

    def test_u16_round_trip(self):
        # Lines 219, 221: U16 serialize/deserialize
        original = ScriptArgument(ScriptArgument.U16, 65535)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored

    def test_u32_round_trip(self):
        # Lines 223, 227: U32 serialize/deserialize
        original = ScriptArgument(ScriptArgument.U32, 4294967295)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored

    def test_u128_round_trip(self):
        # Lines 229, 251: U128 serialize/deserialize
        original = ScriptArgument(ScriptArgument.U128, 2**64 + 1)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored

    def test_u256_round_trip(self):
        # Lines 231, 253: U256 serialize/deserialize
        original = ScriptArgument(ScriptArgument.U256, 2**128 + 99)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored

    def test_address_round_trip(self):
        # Lines 233, 255: ADDRESS serialize/deserialize
        original = ScriptArgument(ScriptArgument.ADDRESS, AccountAddress.ONE)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored

    def test_u8_vector_round_trip(self):
        # Lines 235, 257: U8_VECTOR serialize/deserialize
        original = ScriptArgument(ScriptArgument.U8_VECTOR, b"\x01\x02\x03")
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = ScriptArgument.deserialize(der)
        assert original == restored

    def test_repr_equals_str(self):
        # Line 212: __repr__ delegates to __str__
        arg = ScriptArgument(ScriptArgument.U64, 42)
        assert repr(arg) == str(arg)
        assert "42" in repr(arg)

    def test_eq_returns_not_implemented_for_wrong_type(self):
        # Line 205: __eq__ branch for non-ScriptArgument
        arg = ScriptArgument(ScriptArgument.U64, 1)
        result = arg.__eq__("not_a_script_arg")
        assert result is NotImplemented

    def test_deserialize_unknown_variant_raises(self):
        # Lines 264-265: unknown variant in deserialize
        # Craft a raw byte stream with an invalid variant byte
        data = bytes([99, 0])  # variant=99, dummy value
        der = Deserializer(data)
        with pytest.raises(InvalidInputError):
            ScriptArgument.deserialize(der)


# ---------------------------------------------------------------------------
# Script — construction, str, repr, equality, serialization, deserialization
# ---------------------------------------------------------------------------


class TestScript:
    def test_construction_stores_fields(self):
        # Lines 466-467: __init__ assigns code, ty_args, args
        code = b"\xde\xad\xbe\xef"
        ty_args = [TypeTag(U64Tag())]
        args = [ScriptArgument(ScriptArgument.U64, 7)]
        script = Script(code, ty_args, args)
        assert script.code == code
        assert script.ty_args == ty_args
        assert script.args == args

    def test_str_shows_ty_args_and_args(self):
        # Line 478: __str__ format
        script = Script(b"\x00", [], [])
        s = str(script)
        assert "<" in s and ">" in s

    def test_repr_equals_str(self):
        # Line 484: __repr__ delegates to __str__
        script = Script(b"\x01", [], [])
        assert repr(script) == str(script)

    def test_equality(self):
        # Lines 470-472: __eq__
        a = Script(b"\xab", [TypeTag(U64Tag())], [ScriptArgument(ScriptArgument.U8, 1)])
        b = Script(b"\xab", [TypeTag(U64Tag())], [ScriptArgument(ScriptArgument.U8, 1)])
        assert a == b

    def test_inequality_different_code(self):
        a = Script(b"\x01", [], [])
        b = Script(b"\x02", [], [])
        assert a != b

    def test_eq_returns_not_implemented_for_wrong_type(self):
        # Line 470: __eq__ branch for non-Script
        script = Script(b"\x00", [], [])
        result = script.__eq__("not_a_script")
        assert result is NotImplemented

    def test_bcs_round_trip_empty(self):
        # Lines 488-489, 497-499: serialize/deserialize with empty fields
        original = Script(b"", [], [])
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Script.deserialize(der)
        assert original == restored

    def test_bcs_round_trip_with_args(self):
        # Full serialize/deserialize path
        original = Script(
            b"\xab\xcd\xef",
            [TypeTag(U64Tag())],
            [
                ScriptArgument(ScriptArgument.U64, 100),
                ScriptArgument(ScriptArgument.BOOL, False),
            ],
        )
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Script.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# EntryFunction — __repr__ and direct constructor
# ---------------------------------------------------------------------------


class TestEntryFunctionExtended:
    def test_repr_equals_str(self):
        # Line 384: __repr__ delegates to __str__
        ef = _make_entry_function()
        assert repr(ef) == str(ef)

    def test_direct_constructor(self):
        # Direct EntryFunction constructor (not .natural)
        module = ModuleId.from_str("0x1::coin")
        ser = Serializer()
        ser.u64(42)
        ef = EntryFunction(module, "transfer", [], [ser.output()])
        assert ef.module == module
        assert ef.function == "transfer"
        assert ef.args == [ser.output()]

    def test_deserialization_via_deserialize_method(self):
        # Line 372: EntryFunction.deserialize reachable via BCS round-trip
        original = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag(AccountAddress.ONE, "aptos_coin", "AptosCoin", []))],
            [TransactionArgument(AccountAddress.ONE, Serializer.struct)],
        )
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = EntryFunction.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# TransactionPayload — Multisig variant, __repr__, MODULE_BUNDLE error,
# unknown variant error
# ---------------------------------------------------------------------------


class TestTransactionPayloadExtended:
    def test_wraps_multisig(self):
        # Lines 573-574: Multisig branch in __init__
        multisig = Multisig(AccountAddress.ONE)
        payload = TransactionPayload(multisig)
        assert payload.variant == TransactionPayload.MULTISIG
        assert payload.value == multisig

    def test_repr_equals_str(self):
        # Lines 304, 312: __str__ and __repr__; __repr__ delegates to __str__
        ef = _make_entry_function()
        payload = TransactionPayload(ef)
        assert repr(payload) == str(payload)

    def test_multisig_bcs_round_trip(self):
        # Lines 315, 610-611: deserialize Multisig variant
        multisig = Multisig(AccountAddress.from_hex("0x" + "ab" * 32))
        original = TransactionPayload(multisig)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = TransactionPayload.deserialize(der)
        assert original == restored

    def test_module_bundle_variant_raises_not_implemented(self):
        # Lines 604-606: MODULE_BUNDLE raises NotImplementedError on deserialize
        # Build a byte stream with variant_index=1 (MODULE_BUNDLE)
        ser = Serializer()
        ser.variant_index(TransactionPayload.MODULE_BUNDLE)
        der = Deserializer(ser.output())
        with pytest.raises(NotImplementedError):
            TransactionPayload.deserialize(der)

    def test_unknown_variant_raises_invalid_input(self):
        # Lines 612-615: unknown variant raises InvalidInputError
        ser = Serializer()
        ser.variant_index(99)
        der = Deserializer(ser.output())
        with pytest.raises(InvalidInputError):
            TransactionPayload.deserialize(der)

    def test_eq_returns_not_implemented_for_wrong_type(self):
        # Line 582-583: __eq__ branch for non-TransactionPayload
        payload = TransactionPayload(_make_entry_function())
        result = payload.__eq__("not_a_payload")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# Multisig — construction, str, repr, equality, BCS round-trips
# ---------------------------------------------------------------------------


class TestMultisig:
    def test_construction_without_entry_function(self):
        # Lines 466-467: __init__ with entry_function=None
        multisig = Multisig(AccountAddress.ONE)
        assert multisig.multisig_address == AccountAddress.ONE
        assert multisig.entry_function is None

    def test_construction_with_entry_function(self):
        ef = _make_entry_function()
        multisig = Multisig(AccountAddress.ONE, ef)
        assert multisig.entry_function == ef

    def test_str_contains_address(self):
        # Line 478: __str__
        multisig = Multisig(AccountAddress.ONE)
        s = str(multisig)
        assert "Multisig" in s

    def test_repr_equals_str(self):
        # Line 484: __repr__
        multisig = Multisig(AccountAddress.ONE)
        assert repr(multisig) == str(multisig)

    def test_equality(self):
        # Lines 470-472: __eq__
        a = Multisig(AccountAddress.ONE)
        b = Multisig(AccountAddress.ONE)
        assert a == b

    def test_inequality_different_address(self):
        a = Multisig(AccountAddress.ONE)
        b = Multisig(AccountAddress.from_hex("0x2"))
        assert a != b

    def test_eq_returns_not_implemented_for_wrong_type(self):
        # Line 470: non-Multisig comparison
        multisig = Multisig(AccountAddress.ONE)
        result = multisig.__eq__("not_a_multisig")
        assert result is NotImplemented

    def test_bcs_round_trip_no_entry_function(self):
        # Lines 488-489: serialize with None entry_function; 497-499: deserialize
        original = Multisig(AccountAddress.from_hex("0x" + "12" * 32))
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Multisig.deserialize(der)
        assert original == restored

    def test_bcs_round_trip_with_entry_function(self):
        # Full serialization with an embedded EntryFunction
        ef = _make_entry_function()
        original = Multisig(AccountAddress.from_hex("0x" + "ab" * 32), ef)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = Multisig.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# RawTransaction — __repr__, sign with secp256k1, sign_simulated, and
# chain_id as ChainId object
# ---------------------------------------------------------------------------


class TestRawTransactionExtended:
    def test_repr_equals_str(self):
        # Line 78 (ModuleId.__repr__) exercised transitively; raw transaction has no __repr__
        # But all __str__ fields are exercised. Confirm str contains key fields.
        txn = _make_raw_transaction()
        s = str(txn)
        assert "sequence_number" in s
        assert "max_gas_amount" in s
        assert "chain_id" in s

    def test_chain_id_as_chain_id_object(self):
        # Line 674: else branch — chain_id already a ChainId
        chain = ChainId(4)
        sender = AccountAddress.from_hex("0x" + "ab" * 32)
        payload = TransactionPayload(_make_entry_function())
        txn = RawTransaction(sender, 0, payload, 200_000, 100, 9_999_999_999, chain)
        assert txn.chain_id is chain

    def test_sign_with_secp256k1_returns_single_key_authenticator(self):
        # Lines 746-748: Secp256k1 branch in RawTransaction.sign
        priv = Secp256k1PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        assert isinstance(auth, AccountAuthenticator)
        assert auth.variant == AccountAuthenticator.SINGLE_KEY

    def test_sign_simulated_with_ed25519(self):
        # Lines 763-768: Ed25519PublicKey branch in RawTransaction.sign_simulated
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign_simulated(priv.public_key())
        assert isinstance(auth, AccountAuthenticator)
        assert auth.variant == AccountAuthenticator.ED25519
        # Simulated signature should be all zeros
        inner = auth.authenticator
        assert isinstance(inner, Ed25519Authenticator)
        assert inner.signature.data() == b"\x00" * 64

    def test_sign_simulated_with_secp256k1(self):
        # Lines 770-775: Secp256k1PublicKey branch in RawTransaction.sign_simulated
        priv = Secp256k1PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign_simulated(priv.public_key())
        assert isinstance(auth, AccountAuthenticator)
        assert auth.variant == AccountAuthenticator.SINGLE_KEY

    def test_sign_simulated_unsupported_key_raises(self):
        # Lines 777-779: NotImplementedError for unsupported key type
        txn = _make_raw_transaction()
        with pytest.raises(NotImplementedError):
            txn.sign_simulated("not_a_real_public_key")

    def test_eq_returns_not_implemented_for_wrong_type(self):
        # Line 681-682: __eq__ branch for non-RawTransaction
        txn = _make_raw_transaction()
        result = txn.__eq__("not_a_raw_txn")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# MultiAgentRawTransaction — sign, sign_simulated, verify, full
# deserialize (variant check), RawTransactionWithData.deserialize dispatch
# ---------------------------------------------------------------------------


class TestMultiAgentRawTransactionExtended:
    def test_sign_with_ed25519(self):
        # Lines 893-901: RawTransactionWithData.sign — Ed25519 path
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        secondary = [AccountAddress.from_hex("0x" + "cd" * 32)]
        multi = MultiAgentRawTransaction(txn, secondary)
        auth = multi.sign(priv)
        assert isinstance(auth, AccountAuthenticator)
        assert auth.variant == AccountAuthenticator.ED25519

    def test_sign_with_secp256k1(self):
        # Lines 902-904: RawTransactionWithData.sign — Secp256k1 path
        priv = Secp256k1PrivateKey.generate()
        txn = _make_raw_transaction()
        multi = MultiAgentRawTransaction(txn, [])
        auth = multi.sign(priv)
        assert isinstance(auth, AccountAuthenticator)
        assert auth.variant == AccountAuthenticator.SINGLE_KEY

    def test_sign_simulated_with_ed25519(self):
        # Lines 919-924: RawTransactionWithData.sign_simulated — Ed25519
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        multi = MultiAgentRawTransaction(txn, [])
        auth = multi.sign_simulated(priv.public_key())
        assert auth.variant == AccountAuthenticator.ED25519
        inner = auth.authenticator
        assert isinstance(inner, Ed25519Authenticator)
        assert inner.signature.data() == b"\x00" * 64

    def test_sign_simulated_with_secp256k1(self):
        # Lines 926-931: RawTransactionWithData.sign_simulated — Secp256k1
        priv = Secp256k1PrivateKey.generate()
        txn = _make_raw_transaction()
        multi = MultiAgentRawTransaction(txn, [])
        auth = multi.sign_simulated(priv.public_key())
        assert auth.variant == AccountAuthenticator.SINGLE_KEY

    def test_sign_simulated_unsupported_key_raises(self):
        # Lines 933-935: NotImplementedError for unsupported key type
        txn = _make_raw_transaction()
        multi = MultiAgentRawTransaction(txn, [])
        with pytest.raises(NotImplementedError):
            multi.sign_simulated("bad_key")

    def test_verify_signature(self):
        # Line 945: RawTransactionWithData.verify
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        multi = MultiAgentRawTransaction(txn, [])
        auth = multi.sign(priv)
        sig = auth.authenticator.signature  # type: ignore[union-attr]
        pub = priv.public_key()
        assert multi.verify(pub, sig)

    def test_full_deserialize_with_variant_check(self):
        # Lines 1010-1015: MultiAgentRawTransaction.deserialize reads variant byte
        txn = _make_raw_transaction()
        secondary = [AccountAddress.from_hex("0x" + "cd" * 32)]
        original = MultiAgentRawTransaction(txn, secondary)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MultiAgentRawTransaction.deserialize(der)
        assert restored.secondary_signers == original.secondary_signers

    def test_full_deserialize_wrong_variant_raises(self):
        # Line 1011-1014: wrong variant byte raises InvalidInputError
        # FeePayerRawTransaction uses variant byte 1
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], AccountAddress.ONE)
        ser = Serializer()
        fp_txn.serialize(ser)
        der = Deserializer(ser.output())
        with pytest.raises(InvalidInputError):
            MultiAgentRawTransaction.deserialize(der)

    def test_raw_transaction_with_data_deserialize_multi_agent(self):
        # Lines 959-962: RawTransactionWithData.deserialize dispatches variant 0
        txn = _make_raw_transaction()
        original = MultiAgentRawTransaction(txn, [])
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = RawTransactionWithData.deserialize(der)
        assert isinstance(restored, MultiAgentRawTransaction)

    def test_raw_transaction_with_data_deserialize_fee_payer(self):
        # Lines 963-964: RawTransactionWithData.deserialize dispatches variant 1
        txn = _make_raw_transaction()
        fee_payer = AccountAddress.from_hex("0x" + "ef" * 32)
        original = FeePayerRawTransaction(txn, [], fee_payer)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = RawTransactionWithData.deserialize(der)
        assert isinstance(restored, FeePayerRawTransaction)

    def test_raw_transaction_with_data_deserialize_unknown_variant_raises(self):
        # Lines 965-968: unknown variant raises InvalidInputError
        ser = Serializer()
        ser.u8(99)  # unknown variant
        der = Deserializer(ser.output())
        with pytest.raises(InvalidInputError):
            RawTransactionWithData.deserialize(der)


# ---------------------------------------------------------------------------
# FeePayerRawTransaction — inner(), secondary signers, sign, sign_simulated,
# verify, full deserialize (variant check), none fee_payer round-trip
# ---------------------------------------------------------------------------


class TestFeePayerRawTransactionExtended:
    def test_inner_returns_raw_transaction(self):
        # Line 682 (inner() on FeePayerRawTransaction)
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], AccountAddress.ONE)
        assert fp_txn.inner() is txn

    def test_secondary_signers_stored(self):
        # Line 746: FeePayerRawTransaction with secondary signers
        txn = _make_raw_transaction()
        secondary = [AccountAddress.from_hex("0x" + "22" * 32)]
        fee_payer = AccountAddress.from_hex("0x" + "ef" * 32)
        fp_txn = FeePayerRawTransaction(txn, secondary, fee_payer)
        assert fp_txn.secondary_signers == secondary

    def test_sign_with_ed25519(self):
        # Lines 763-777: FeePayerRawTransaction.sign (via base class) — Ed25519 path
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], AccountAddress.ONE)
        auth = fp_txn.sign(priv)
        assert isinstance(auth, AccountAuthenticator)
        assert auth.variant == AccountAuthenticator.ED25519

    def test_sign_with_secp256k1(self):
        # FeePayerRawTransaction.sign — Secp256k1 path
        priv = Secp256k1PrivateKey.generate()
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], AccountAddress.ONE)
        auth = fp_txn.sign(priv)
        assert auth.variant == AccountAuthenticator.SINGLE_KEY

    def test_sign_simulated_with_ed25519(self):
        # Lines 763-777: sign_simulated Ed25519 path
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], AccountAddress.ONE)
        auth = fp_txn.sign_simulated(priv.public_key())
        assert auth.variant == AccountAuthenticator.ED25519
        inner = auth.authenticator
        assert isinstance(inner, Ed25519Authenticator)
        assert inner.signature.data() == b"\x00" * 64

    def test_sign_simulated_with_secp256k1(self):
        # sign_simulated Secp256k1 path
        priv = Secp256k1PrivateKey.generate()
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], AccountAddress.ONE)
        auth = fp_txn.sign_simulated(priv.public_key())
        assert auth.variant == AccountAuthenticator.SINGLE_KEY

    def test_verify_signature(self):
        # RawTransactionWithData.verify for FeePayerRawTransaction
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        fp_txn = FeePayerRawTransaction(txn, [], AccountAddress.ONE)
        auth = fp_txn.sign(priv)
        sig = auth.authenticator.signature  # type: ignore[union-attr]
        pub = priv.public_key()
        assert fp_txn.verify(pub, sig)

    def test_full_deserialize_with_variant_check(self):
        # Lines 1081-1086: FeePayerRawTransaction.deserialize reads variant byte
        txn = _make_raw_transaction()
        fee_payer = AccountAddress.from_hex("0x" + "ef" * 32)
        original = FeePayerRawTransaction(txn, [], fee_payer)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = FeePayerRawTransaction.deserialize(der)
        assert restored.fee_payer == original.fee_payer

    def test_full_deserialize_wrong_variant_raises(self):
        # Lines 1082-1085: wrong variant byte raises InvalidInputError
        txn = _make_raw_transaction()
        secondary = [AccountAddress.from_hex("0x" + "cd" * 32)]
        multi = MultiAgentRawTransaction(txn, secondary)
        ser = Serializer()
        multi.serialize(ser)
        der = Deserializer(ser.output())
        with pytest.raises(InvalidInputError):
            FeePayerRawTransaction.deserialize(der)

    def test_none_fee_payer_round_trip_deserializes_as_none(self):
        # When fee_payer=None, wire has AccountAddress.ZERO; deserialized back as None
        txn = _make_raw_transaction()
        original = FeePayerRawTransaction(txn, [], None)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        variant = der.u8()
        assert variant == 1
        restored = FeePayerRawTransaction._deserialize_inner(der)
        assert restored.fee_payer is None

    def test_bcs_round_trip_with_secondary_signers(self):
        # Lines 763-777: Full round-trip with non-empty secondary signers
        txn = _make_raw_transaction()
        secondary = [AccountAddress.from_hex("0x" + "22" * 32)]
        fee_payer = AccountAddress.from_hex("0x" + "ef" * 32)
        original = FeePayerRawTransaction(txn, secondary, fee_payer)
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        variant = der.u8()
        assert variant == 1
        restored = FeePayerRawTransaction._deserialize_inner(der)
        assert restored.secondary_signers == secondary
        assert restored.fee_payer == fee_payer


# ---------------------------------------------------------------------------
# SignedTransaction — Secp256k1 path (SingleSenderAuthenticator wrapping),
# __str__/__repr__, verify with MultiAgentAuthenticator,
# verify with FeePayerAuthenticator
# ---------------------------------------------------------------------------


class TestSignedTransactionExtended:
    def test_signed_with_secp256k1_wraps_in_single_sender(self):
        # Lines 1152-1154: SingleKey AccountAuthenticator → SingleSenderAuthenticator
        priv = Secp256k1PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        signed = SignedTransaction(txn, auth)
        # For SingleKey, SignedTransaction wraps it in SingleSenderAuthenticator
        assert signed.authenticator.variant == TransactionAuthenticator.SINGLE_SENDER

    def test_signed_with_secp256k1_verifies(self):
        # Verify works through SingleSender wrapping
        priv = Secp256k1PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        signed = SignedTransaction(txn, auth)
        assert signed.verify()

    def test_str_contains_transaction_and_authenticator(self):
        # Lines 1164, 1171: __str__ includes both transaction and authenticator text
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        signed = SignedTransaction(txn, auth)
        s = str(signed)
        assert "Transaction" in s
        assert "Authenticator" in s

    def test_repr_equals_str(self):
        # Line 1174: __repr__ delegates to __str__
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        signed = SignedTransaction(txn, auth)
        assert repr(signed) == str(signed)

    def test_eq_returns_not_implemented_for_wrong_type(self):
        # Lines 1162-1164: __eq__ for non-SignedTransaction
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        signed = SignedTransaction(txn, auth)
        result = signed.__eq__("not_a_signed_txn")
        assert result is NotImplemented

    def test_verify_with_multi_agent_authenticator(self):
        # Lines 1201-1204: verify takes MultiAgentAuthenticator branch
        sender_priv = Ed25519PrivateKey.generate()
        secondary_priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        secondary_addr = AccountAddress.from_hex("0x" + "cd" * 32)

        multi_raw = MultiAgentRawTransaction(txn, [secondary_addr])

        # Both sign with the WITH_DATA prefix
        sender_auth = multi_raw.sign(sender_priv)
        secondary_auth = multi_raw.sign(secondary_priv)

        multi_auth = MultiAgentAuthenticator(
            sender_auth,
            [(secondary_addr, secondary_auth)],
        )
        txn_auth = TransactionAuthenticator(multi_auth)
        signed = SignedTransaction(txn, txn_auth)
        assert signed.verify()

    def test_verify_with_fee_payer_authenticator(self):
        # Lines 1205-1211: verify takes FeePayerAuthenticator branch
        sender_priv = Ed25519PrivateKey.generate()
        fee_payer_priv = Ed25519PrivateKey.generate()
        fee_payer_addr = AccountAddress.from_hex("0x" + "ef" * 32)
        txn = _make_raw_transaction()

        fp_raw = FeePayerRawTransaction(txn, [], fee_payer_addr)

        sender_auth = fp_raw.sign(sender_priv)
        fee_payer_auth = fp_raw.sign(fee_payer_priv)

        fp_authenticator = FeePayerAuthenticator(
            sender_auth,
            [],
            (fee_payer_addr, fee_payer_auth),
        )
        txn_auth = TransactionAuthenticator(fp_authenticator)
        signed = SignedTransaction(txn, txn_auth)
        assert signed.verify()

    def test_bytes_round_trip_deserialization(self):
        # Lines 1180-1184 (bytes()) already tested; also test deserialize path
        priv = Ed25519PrivateKey.generate()
        txn = _make_raw_transaction()
        auth = txn.sign(priv)
        original = SignedTransaction(txn, auth)
        raw = original.bytes()
        der = Deserializer(raw)
        restored = SignedTransaction.deserialize(der)
        assert original == restored


# ---------------------------------------------------------------------------
# Miscellaneous — cover remaining reachable lines
# ---------------------------------------------------------------------------


class TestMiscellaneous:
    def test_entry_function_eq_returns_not_implemented_for_wrong_type(self):
        # Line 372: EntryFunction.__eq__ branch for non-EntryFunction
        ef = _make_entry_function()
        result = ef.__eq__("not_an_entry_function")
        assert result is NotImplemented

    def test_raw_transaction_with_data_serialize_raises_not_implemented(self):
        # Line 949: RawTransactionWithData.serialize is abstract (raises NotImplementedError)
        # We create a minimal subclass that does not override serialize to hit the base.
        class _BareVariant(RawTransactionWithData):
            def __init__(self) -> None:
                self.raw_transaction = _make_raw_transaction()

        bare = _BareVariant()
        ser = Serializer()
        with pytest.raises(NotImplementedError):
            bare.serialize(ser)

    def test_module_bundle_construction_raises(self):
        # Line 515: ModuleBundle.__init__ always raises NotImplementedError
        from aptos_sdk.transactions import ModuleBundle

        with pytest.raises(NotImplementedError):
            ModuleBundle()

    def test_module_bundle_deserialize_raises(self):
        # Line 521: ModuleBundle.deserialize raises NotImplementedError
        from aptos_sdk.transactions import ModuleBundle

        der = Deserializer(b"")
        with pytest.raises(NotImplementedError):
            ModuleBundle.deserialize(der)
