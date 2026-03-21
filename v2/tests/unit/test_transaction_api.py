"""Unit tests for TransactionApi — build, simulate, sign, submit, wait pipeline."""

import time

import pytest
from aioresponses import aioresponses

from aptos_sdk_v2.account.account import Account
from aptos_sdk_v2.api.http_client import HttpClient
from aptos_sdk_v2.api.transaction_api import TransactionApi
from aptos_sdk_v2.config import AptosConfig
from aptos_sdk_v2.errors import TransactionFailedError, TransactionTimeoutError
from aptos_sdk_v2.transactions.payload import EntryFunction, TransactionPayload
from aptos_sdk_v2.types.account_address import AccountAddress
from aptos_sdk_v2.types.type_tag import StructTag, TypeTag

NODE = "https://fullnode.devnet.aptoslabs.com/v1"
SENDER = AccountAddress.from_str("0x1")
RECIPIENT = AccountAddress.from_str("0x2")


def _dummy_payload():
    """Create a minimal transfer payload for testing."""
    from aptos_sdk_v2.bcs import Serializer
    from aptos_sdk_v2.transactions.payload import TransactionArgument

    ef = EntryFunction.natural(
        "0x1::coin",
        "transfer",
        [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
        [
            TransactionArgument(RECIPIENT, Serializer.struct),
            TransactionArgument(1000, Serializer.u64),
        ],
    )
    return TransactionPayload(ef)


@pytest.fixture
def config():
    return AptosConfig(transaction_wait_secs=5)


@pytest.fixture
async def api(config):
    client = HttpClient(config)
    yield TransactionApi(config, client)
    await client.close()


@pytest.fixture
def account():
    return Account.generate()


class TestBuild:
    async def test_build_fetches_seq_and_chain_id(self, api):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{SENDER}", payload={"sequence_number": "7"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(SENDER, _dummy_payload())
            assert raw.sequence_number == 7
            assert raw.chain_id == 4
            assert raw.sender == SENDER

    async def test_build_with_explicit_sequence_number(self, api):
        with aioresponses() as m:
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(SENDER, _dummy_payload(), sequence_number=99)
            assert raw.sequence_number == 99
            assert raw.chain_id == 4

    async def test_chain_id_cached(self, api):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{SENDER}", payload={"sequence_number": "0"})
            m.get(NODE, payload={"chain_id": 4})
            await api.build(SENDER, _dummy_payload())

        # Second build should NOT need a chain_id fetch
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{SENDER}", payload={"sequence_number": "1"})
            raw = await api.build(SENDER, _dummy_payload())
            assert raw.chain_id == 4
            assert raw.sequence_number == 1

    async def test_build_uses_config_defaults(self, api, config):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{SENDER}", payload={"sequence_number": "0"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(SENDER, _dummy_payload())
            assert raw.max_gas_amount == config.max_gas_amount
            assert raw.gas_unit_price == config.gas_unit_price

    async def test_build_custom_gas(self, api):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{SENDER}", payload={"sequence_number": "0"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(SENDER, _dummy_payload(), max_gas_amount=5000, gas_unit_price=200)
            assert raw.max_gas_amount == 5000
            assert raw.gas_unit_price == 200

    async def test_build_custom_expiration(self, api):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{SENDER}", payload={"sequence_number": "0"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(SENDER, _dummy_payload(), expiration_timestamps_secs=9999999)
            assert raw.expiration_timestamps_secs == 9999999


class TestSimulate:
    async def test_simulate(self, api, account):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{account.address}", payload={"sequence_number": "0"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(account.address, _dummy_payload())

        with aioresponses() as m:
            m.post(
                f"{NODE}/transactions/simulate",
                payload=[{"success": True, "gas_used": "100"}],
            )
            result = await api.simulate(raw, account.public_key)
            assert isinstance(result, list)
            assert result[0]["success"] is True


class TestSubmit:
    async def test_submit_returns_hash(self, api, account):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{account.address}", payload={"sequence_number": "0"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(account.address, _dummy_payload())

        signed = api.sign(raw, account)
        with aioresponses() as m:
            m.post(f"{NODE}/transactions", payload={"hash": "0xabc123"})
            result = await api.submit(signed)
            assert result == "0xabc123"


class TestWaitForTransaction:
    async def test_immediate_success(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/transactions/by_hash/0xabc",
                payload={"type": "user_transaction", "success": True, "hash": "0xabc"},
            )
            result = await api.wait_for_transaction("0xabc")
            assert result["success"] is True

    async def test_pending_then_success(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/transactions/by_hash/0xabc",
                payload={"type": "pending_transaction"},
            )
            m.get(
                f"{NODE}/transactions/by_hash/0xabc",
                payload={"type": "user_transaction", "success": True},
            )
            result = await api.wait_for_transaction("0xabc")
            assert result["success"] is True

    async def test_failed_raises(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/transactions/by_hash/0xfail",
                payload={
                    "type": "user_transaction",
                    "success": False,
                    "vm_status": "ABORT_CODE",
                },
            )
            with pytest.raises(TransactionFailedError) as exc_info:
                await api.wait_for_transaction("0xfail")
            assert exc_info.value.txn_hash == "0xfail"
            assert exc_info.value.vm_status == "ABORT_CODE"

    async def test_timeout_raises(self, api, monkeypatch):
        call_count = 0

        def fake_time():
            nonlocal call_count
            call_count += 1
            # First call: deadline = base + 5
            # Second call (loop check): past deadline
            if call_count <= 1:
                return 1000.0
            return 1006.0  # Past the 5s deadline

        monkeypatch.setattr(time, "time", fake_time)
        with pytest.raises(TransactionTimeoutError) as exc_info:
            await api.wait_for_transaction("0xtimeout")
        assert exc_info.value.txn_hash == "0xtimeout"

    async def test_transient_api_error_then_success(self):
        """Error must propagate out of HttpClient to trigger wait_for_transaction's handler."""
        config = AptosConfig(transaction_wait_secs=5, max_retries=0)
        client = HttpClient(config)
        api = TransactionApi(config, client)
        try:
            with aioresponses() as m:
                # max_retries=0 → HttpClient raises immediately on 500
                m.get(
                    f"{NODE}/transactions/by_hash/0xretry",
                    status=500,
                    body="server error",
                )
                m.get(
                    f"{NODE}/transactions/by_hash/0xretry",
                    payload={"type": "user_transaction", "success": True},
                )
                result = await api.wait_for_transaction("0xretry")
                assert result["success"] is True
        finally:
            await client.close()


class TestSignAndSubmit:
    async def test_sign_and_submit(self, api, account):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{account.address}", payload={"sequence_number": "0"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(account.address, _dummy_payload())

        with aioresponses() as m:
            m.post(f"{NODE}/transactions", payload={"hash": "0xsubmitted"})
            result = await api.sign_and_submit(raw, account)
            assert result == "0xsubmitted"


class TestSignSubmitAndWait:
    async def test_full_pipeline(self, api, account):
        with aioresponses() as m:
            m.get(f"{NODE}/accounts/{account.address}", payload={"sequence_number": "0"})
            m.get(NODE, payload={"chain_id": 4})
            raw = await api.build(account.address, _dummy_payload())

        with aioresponses() as m:
            m.post(f"{NODE}/transactions", payload={"hash": "0xfull"})
            m.get(
                f"{NODE}/transactions/by_hash/0xfull",
                payload={"type": "user_transaction", "success": True, "hash": "0xfull"},
            )
            result = await api.sign_submit_and_wait(raw, account)
            assert result["success"] is True


class TestGetters:
    async def test_get_by_hash(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/transactions/by_hash/0xabc",
                payload={"hash": "0xabc", "type": "user_transaction"},
            )
            result = await api.get_by_hash("0xabc")
            assert result["hash"] == "0xabc"

    async def test_get_by_version(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/transactions/by_version/42",
                payload={"version": "42", "type": "user_transaction"},
            )
            result = await api.get_by_version(42)
            assert result["version"] == "42"
