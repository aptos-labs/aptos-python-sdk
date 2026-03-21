"""Unit tests for orderless transaction types and BCS option encoding."""

import pytest
from aioresponses import aioresponses

from aptos_sdk_v2.api.http_client import HttpClient
from aptos_sdk_v2.api.transaction_api import TransactionApi
from aptos_sdk_v2.bcs import Deserializer, Serializer
from aptos_sdk_v2.config import AptosConfig
from aptos_sdk_v2.errors import BcsDeserializationError
from aptos_sdk_v2.transactions.payload import (
    EntryFunction,
    Script,
    TransactionArgument,
    TransactionExecutable,
    TransactionExtraConfig,
    TransactionInnerPayload,
    TransactionPayload,
)
from aptos_sdk_v2.types.account_address import AccountAddress
from aptos_sdk_v2.types.type_tag import StructTag, TypeTag

NODE = "https://fullnode.devnet.aptoslabs.com/v1"
SENDER = AccountAddress.from_str("0x1")
RECIPIENT = AccountAddress.from_str("0x2")


def _transfer_entry_function():
    return EntryFunction.natural(
        "0x1::coin",
        "transfer",
        [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
        [
            TransactionArgument(RECIPIENT, Serializer.struct),
            TransactionArgument(1000, Serializer.u64),
        ],
    )


class TestBcsOption:
    def test_option_none(self):
        ser = Serializer()
        ser.option(None, Serializer.u64)
        data = ser.output()
        assert data == b"\x00"

        result = Deserializer(data).option(Deserializer.u64)
        assert result is None

    def test_option_some_u64(self):
        ser = Serializer()
        ser.option(42, Serializer.u64)
        data = ser.output()
        # bool(true) + u64(42)
        assert data[0:1] == b"\x01"

        result = Deserializer(data).option(Deserializer.u64)
        assert result == 42

    def test_option_some_struct(self):
        addr = AccountAddress.from_str("0x000000000000000000000000000000000000000000000000000000000000dead")
        ser = Serializer()
        ser.option(addr, Serializer.struct)
        data = ser.output()

        result = Deserializer(data).option(AccountAddress.deserialize)
        assert result == addr


class TestTransactionExecutable:
    def test_entry_function_round_trip(self):
        ef = _transfer_entry_function()
        exe = TransactionExecutable(ef)
        assert exe.variant == TransactionExecutable.ENTRY_FUNCTION

        ser = Serializer()
        exe.serialize(ser)
        result = TransactionExecutable.deserialize(Deserializer(ser.output()))
        assert result == exe

    def test_script_round_trip(self):
        script = Script(b"\x00\x01\x02", [], [])
        exe = TransactionExecutable(script)
        assert exe.variant == TransactionExecutable.SCRIPT

        ser = Serializer()
        exe.serialize(ser)
        result = TransactionExecutable.deserialize(Deserializer(ser.output()))
        assert result == exe

    def test_invalid_type_raises(self):
        with pytest.raises(TypeError):
            TransactionExecutable("bad")  # type: ignore[arg-type]

    def test_invalid_variant_deserialize(self):
        ser = Serializer()
        ser.uleb128(99)
        with pytest.raises(BcsDeserializationError):
            TransactionExecutable.deserialize(Deserializer(ser.output()))

    def test_eq_not_executable(self):
        ef = _transfer_entry_function()
        exe = TransactionExecutable(ef)
        assert exe != "not an executable"


class TestTransactionExtraConfig:
    def test_nonce_only(self):
        config = TransactionExtraConfig(replay_protection_nonce=12345)
        ser = Serializer()
        config.serialize(ser)
        result = TransactionExtraConfig.deserialize(Deserializer(ser.output()))
        assert result == config
        assert result.multisig_address is None
        assert result.replay_protection_nonce == 12345

    def test_multisig_only(self):
        addr = AccountAddress.from_str("0x000000000000000000000000000000000000000000000000000000000000beef")
        config = TransactionExtraConfig(multisig_address=addr)
        ser = Serializer()
        config.serialize(ser)
        result = TransactionExtraConfig.deserialize(Deserializer(ser.output()))
        assert result == config
        assert result.multisig_address == addr
        assert result.replay_protection_nonce is None

    def test_both_fields(self):
        addr = AccountAddress.from_str("0x000000000000000000000000000000000000000000000000000000000000cafe")
        config = TransactionExtraConfig(
            multisig_address=addr, replay_protection_nonce=999
        )
        ser = Serializer()
        config.serialize(ser)
        result = TransactionExtraConfig.deserialize(Deserializer(ser.output()))
        assert result == config

    def test_neither_field(self):
        config = TransactionExtraConfig()
        ser = Serializer()
        config.serialize(ser)
        result = TransactionExtraConfig.deserialize(Deserializer(ser.output()))
        assert result == config
        assert result.multisig_address is None
        assert result.replay_protection_nonce is None

    def test_eq_not_config(self):
        config = TransactionExtraConfig()
        assert config != "x"

    def test_invalid_variant_deserialize(self):
        ser = Serializer()
        ser.uleb128(5)
        with pytest.raises(BcsDeserializationError):
            TransactionExtraConfig.deserialize(Deserializer(ser.output()))


class TestTransactionInnerPayload:
    def test_round_trip(self):
        ef = _transfer_entry_function()
        inner = TransactionInnerPayload(
            executable=TransactionExecutable(ef),
            extra_config=TransactionExtraConfig(replay_protection_nonce=42),
        )
        ser = Serializer()
        inner.serialize(ser)
        result = TransactionInnerPayload.deserialize(Deserializer(ser.output()))
        assert result == inner

    def test_eq_not_inner(self):
        ef = _transfer_entry_function()
        inner = TransactionInnerPayload(
            executable=TransactionExecutable(ef),
            extra_config=TransactionExtraConfig(),
        )
        assert inner != "x"

    def test_invalid_variant_deserialize(self):
        ser = Serializer()
        ser.uleb128(7)
        with pytest.raises(BcsDeserializationError):
            TransactionInnerPayload.deserialize(Deserializer(ser.output()))


class TestTransactionPayloadVariant4:
    def test_round_trip(self):
        ef = _transfer_entry_function()
        inner = TransactionInnerPayload(
            executable=TransactionExecutable(ef),
            extra_config=TransactionExtraConfig(replay_protection_nonce=9999),
        )
        tp = TransactionPayload(inner)
        assert tp.variant == TransactionPayload.PAYLOAD

        ser = Serializer()
        tp.serialize(ser)
        result = TransactionPayload.deserialize(Deserializer(ser.output()))
        assert result == tp

    def test_str(self):
        ef = _transfer_entry_function()
        inner = TransactionInnerPayload(
            executable=TransactionExecutable(ef),
            extra_config=TransactionExtraConfig(),
        )
        tp = TransactionPayload(inner)
        # Should not raise
        str(tp)


class TestTransactionApiBuildOrderless:
    @pytest.fixture
    def config(self):
        return AptosConfig(transaction_wait_secs=5)

    @pytest.fixture
    async def api(self, config):
        client = HttpClient(config)
        yield TransactionApi(config, client)
        await client.close()

    async def test_build_with_nonce_wraps_payload(self, api):
        payload = TransactionPayload(_transfer_entry_function())
        with aioresponses() as m:
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(
                SENDER, payload, replay_protection_nonce=12345
            )
        # Sequence number defaults to 0 for orderless
        assert raw.sequence_number == 0
        # Payload should be wrapped in variant 4
        assert raw.payload.variant == TransactionPayload.PAYLOAD
        assert isinstance(raw.payload.value, TransactionInnerPayload)
        assert raw.payload.value.extra_config.replay_protection_nonce == 12345

    async def test_build_with_nonce_and_explicit_seq(self, api):
        payload = TransactionPayload(_transfer_entry_function())
        with aioresponses() as m:
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(
                SENDER,
                payload,
                sequence_number=42,
                replay_protection_nonce=99,
            )
        assert raw.sequence_number == 42

    async def test_build_without_nonce_unchanged(self, api):
        payload = TransactionPayload(_transfer_entry_function())
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{SENDER}", payload={"sequence_number": "5"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(SENDER, payload)
        assert raw.sequence_number == 5
        assert raw.payload.variant == TransactionPayload.ENTRY_FUNCTION
