# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.transaction_builder — TransactionBuilder fluent API.
"""

import time

import pytest

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.bcs import Serializer
from aptos_sdk.chain_id import ChainId
from aptos_sdk.errors import (
    MissingChainIdError,
    MissingPayloadError,
    MissingSenderError,
)
from aptos_sdk.transaction_builder import TransactionBuilder
from aptos_sdk.transactions import (
    EntryFunction,
    FeePayerRawTransaction,
    MultiAgentRawTransaction,
    RawTransaction,
    TransactionPayload,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


SENDER = AccountAddress.from_hex("0x" + "ab" * 32)
CHAIN = ChainId(4)


def _base_builder() -> TransactionBuilder:
    """Return a builder with all required fields set."""
    return (
        TransactionBuilder()
        .sender(SENDER)
        .chain_id(CHAIN)
        .entry_function("0x1::aptos_account", "transfer", [], [])
    )


# ---------------------------------------------------------------------------
# Required-field validation
# ---------------------------------------------------------------------------


class TestRequiredFieldValidation:
    def test_missing_sender_raises(self):
        builder = (
            TransactionBuilder()
            .chain_id(CHAIN)
            .entry_function("0x1::aptos_account", "transfer", [], [])
        )
        with pytest.raises(MissingSenderError):
            builder.build()

    def test_missing_payload_raises(self):
        builder = TransactionBuilder().sender(SENDER).chain_id(CHAIN)
        with pytest.raises(MissingPayloadError):
            builder.build()

    def test_missing_chain_id_raises(self):
        builder = (
            TransactionBuilder()
            .sender(SENDER)
            .entry_function("0x1::aptos_account", "transfer", [], [])
        )
        with pytest.raises(MissingChainIdError):
            builder.build()


# ---------------------------------------------------------------------------
# Successful build
# ---------------------------------------------------------------------------


class TestSuccessfulBuild:
    def test_build_returns_raw_transaction(self):
        txn = _base_builder().build()
        assert isinstance(txn, RawTransaction)

    def test_sender_set_correctly(self):
        txn = _base_builder().build()
        assert isinstance(txn, RawTransaction)
        assert txn.sender == SENDER

    def test_chain_id_set_correctly(self):
        txn = _base_builder().build()
        assert isinstance(txn, RawTransaction)
        assert txn.chain_id == CHAIN

    def test_default_sequence_number_is_zero(self):
        txn = _base_builder().build()
        assert isinstance(txn, RawTransaction)
        assert txn.sequence_number == 0

    def test_default_max_gas_amount(self):
        txn = _base_builder().build()
        assert isinstance(txn, RawTransaction)
        assert txn.max_gas_amount == 200_000

    def test_default_gas_unit_price(self):
        txn = _base_builder().build()
        assert isinstance(txn, RawTransaction)
        assert txn.gas_unit_price == 100

    def test_default_expiration_is_60_seconds_from_now(self):
        before = int(time.time()) + 55
        txn = _base_builder().build()
        after = int(time.time()) + 65
        assert isinstance(txn, RawTransaction)
        assert before <= txn.expiration_timestamp_secs <= after


# ---------------------------------------------------------------------------
# Optional-field setters
# ---------------------------------------------------------------------------


class TestOptionalFieldSetters:
    def test_sequence_number(self):
        txn = _base_builder().sequence_number(7).build()
        assert isinstance(txn, RawTransaction)
        assert txn.sequence_number == 7

    def test_max_gas_amount(self):
        txn = _base_builder().max_gas_amount(50_000).build()
        assert isinstance(txn, RawTransaction)
        assert txn.max_gas_amount == 50_000

    def test_gas_unit_price(self):
        txn = _base_builder().gas_unit_price(200).build()
        assert isinstance(txn, RawTransaction)
        assert txn.gas_unit_price == 200

    def test_expiration(self):
        expiry = int(time.time()) + 3600
        txn = _base_builder().expiration(expiry).build()
        assert isinstance(txn, RawTransaction)
        assert txn.expiration_timestamp_secs == expiry


# ---------------------------------------------------------------------------
# entry_function convenience setter
# ---------------------------------------------------------------------------


class TestEntryFunctionSetter:
    def test_entry_function_sets_payload(self):
        ser = Serializer()
        ser.u64(100)
        txn = (
            _base_builder()
            .entry_function(
                "0x1::coin",
                "transfer",
                [],
                [ser.output()],
            )
            .build()
        )
        assert isinstance(txn, RawTransaction)
        payload = txn.payload
        assert payload.variant == TransactionPayload.ENTRY_FUNCTION
        ef = payload.value
        assert isinstance(ef, EntryFunction)
        assert ef.function == "transfer"


# ---------------------------------------------------------------------------
# payload() direct setter
# ---------------------------------------------------------------------------


class TestPayloadSetter:
    def test_direct_payload_setter(self):
        ef = EntryFunction.natural("0x1::aptos_account", "transfer", [], [])
        payload = TransactionPayload(ef)
        txn = (
            TransactionBuilder().sender(SENDER).chain_id(CHAIN).payload(payload).build()
        )
        assert isinstance(txn, RawTransaction)
        assert txn.payload == payload


# ---------------------------------------------------------------------------
# secondary_signers → MultiAgentRawTransaction
# ---------------------------------------------------------------------------


class TestSecondarySigners:
    def test_secondary_signers_produces_multi_agent(self):
        secondary = [AccountAddress.from_hex("0x" + "cd" * 32)]
        txn = _base_builder().secondary_signers(secondary).build()
        assert isinstance(txn, MultiAgentRawTransaction)

    def test_secondary_signers_stored_correctly(self):
        secondary = [AccountAddress.from_hex("0x" + "cd" * 32)]
        txn = _base_builder().secondary_signers(secondary).build()
        assert isinstance(txn, MultiAgentRawTransaction)
        assert txn.secondary_signers == secondary


# ---------------------------------------------------------------------------
# fee_payer → FeePayerRawTransaction
# ---------------------------------------------------------------------------


class TestFeePayer:
    def test_fee_payer_with_address_produces_fee_payer_txn(self):
        fp_addr = AccountAddress.from_hex("0x" + "ef" * 32)
        txn = _base_builder().fee_payer(fp_addr).build()
        assert isinstance(txn, FeePayerRawTransaction)
        assert txn.fee_payer == fp_addr

    def test_fee_payer_none_produces_fee_payer_txn(self):
        txn = _base_builder().fee_payer(None).build()
        assert isinstance(txn, FeePayerRawTransaction)
        assert txn.fee_payer is None

    def test_fee_payer_called_with_no_args_produces_fee_payer_txn(self):
        txn = _base_builder().fee_payer().build()
        assert isinstance(txn, FeePayerRawTransaction)

    def test_fee_payer_takes_precedence_over_secondary_signers(self):
        secondary = [AccountAddress.from_hex("0x" + "cd" * 32)]
        fp_addr = AccountAddress.from_hex("0x" + "ef" * 32)
        txn = _base_builder().secondary_signers(secondary).fee_payer(fp_addr).build()
        # fee_payer takes precedence — should produce FeePayerRawTransaction
        assert isinstance(txn, FeePayerRawTransaction)


# ---------------------------------------------------------------------------
# Fluent chaining
# ---------------------------------------------------------------------------


class TestFluentChaining:
    def test_all_setters_return_self(self):
        builder = TransactionBuilder()
        result = builder.sender(SENDER)
        assert result is builder

        result = builder.chain_id(CHAIN)
        assert result is builder

        result = builder.entry_function("0x1::aptos_account", "transfer", [], [])
        assert result is builder

        result = builder.sequence_number(0)
        assert result is builder

        result = builder.max_gas_amount(100_000)
        assert result is builder

        result = builder.gas_unit_price(50)
        assert result is builder

        result = builder.expiration(int(time.time()) + 60)
        assert result is builder

    def test_full_chain(self):
        txn = (
            TransactionBuilder()
            .sender(AccountAddress.from_hex("0x" + "ab" * 32))
            .chain_id(ChainId(4))
            .entry_function("0x1::aptos_account", "transfer", [], [])
            .sequence_number(5)
            .max_gas_amount(100_000)
            .gas_unit_price(150)
            .expiration(int(time.time()) + 300)
            .build()
        )
        assert isinstance(txn, RawTransaction)
        assert txn.sequence_number == 5
        assert txn.max_gas_amount == 100_000
        assert txn.gas_unit_price == 150
