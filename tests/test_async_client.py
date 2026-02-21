# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.async_client — LedgerInfo, AccountInfo, Resource,
GasEstimate, Transaction dataclasses, RestClient, and FaucetClient.

Uses httpx mock transport to avoid real network calls.
"""

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import (
    AccountInfo,
    FaucetClient,
    GasEstimate,
    LedgerInfo,
    Resource,
    RestClient,
    Transaction,
)
from aptos_sdk.errors import (
    ApiError,
    AptosTimeoutError,
    BadRequestError,
    ConflictError,
    InternalServerError,
    NotFoundError,
    RateLimitedError,
    VmError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_response(data: Any, status_code: int = 200) -> httpx.Response:
    """Build an httpx.Response with JSON body."""
    return httpx.Response(
        status_code=status_code,
        json=data,
        request=httpx.Request("GET", "https://test"),
    )


def _text_response(text: str, status_code: int = 200) -> httpx.Response:
    """Build an httpx.Response with text body."""
    return httpx.Response(
        status_code=status_code,
        text=text,
        request=httpx.Request("GET", "https://test"),
    )


SAMPLE_LEDGER_INFO: dict[str, Any] = {
    "chain_id": 4,
    "epoch": "100",
    "ledger_version": "500000",
    "oldest_ledger_version": "0",
    "ledger_timestamp": "1700000000000000",
    "block_height": "100000",
    "oldest_block_height": "0",
}

SAMPLE_ACCOUNT_INFO: dict[str, Any] = {
    "sequence_number": "42",
    "authentication_key": "0x" + "ab" * 32,
}


# ---------------------------------------------------------------------------
# LedgerInfo
# ---------------------------------------------------------------------------


class TestLedgerInfo:
    def test_from_json(self):
        info = LedgerInfo.from_json(SAMPLE_LEDGER_INFO)
        assert info.chain_id == 4
        assert info.epoch == 100
        assert info.ledger_version == 500_000
        assert info.oldest_ledger_version == 0
        assert info.ledger_timestamp == 1_700_000_000_000_000
        assert info.block_height == 100_000
        assert info.oldest_block_height == 0

    def test_from_json_coerces_strings_to_int(self):
        info = LedgerInfo.from_json(SAMPLE_LEDGER_INFO)
        assert isinstance(info.ledger_version, int)
        assert isinstance(info.epoch, int)


# ---------------------------------------------------------------------------
# AccountInfo
# ---------------------------------------------------------------------------


class TestAccountInfo:
    def test_from_json(self):
        info = AccountInfo.from_json(SAMPLE_ACCOUNT_INFO)
        assert info.sequence_number == 42
        assert info.authentication_key == "0x" + "ab" * 32

    def test_from_json_coerces_string(self):
        info = AccountInfo.from_json(SAMPLE_ACCOUNT_INFO)
        assert isinstance(info.sequence_number, int)


# ---------------------------------------------------------------------------
# Resource
# ---------------------------------------------------------------------------


class TestResource:
    def test_from_json(self):
        raw = {
            "type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            "data": {"coin": {"value": "12345"}},
        }
        res = Resource.from_json(raw)
        assert res.type == "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
        assert res.data["coin"]["value"] == "12345"


# ---------------------------------------------------------------------------
# GasEstimate
# ---------------------------------------------------------------------------


class TestGasEstimate:
    def test_from_json_all_fields(self):
        raw = {
            "gas_estimate": 100,
            "deprioritized_gas_estimate": 50,
            "prioritized_gas_estimate": 200,
        }
        est = GasEstimate.from_json(raw)
        assert est.gas_estimate == 100
        assert est.deprioritized_gas_estimate == 50
        assert est.prioritized_gas_estimate == 200

    def test_from_json_optional_fields_missing(self):
        raw = {"gas_estimate": 100}
        est = GasEstimate.from_json(raw)
        assert est.gas_estimate == 100
        assert est.deprioritized_gas_estimate is None
        assert est.prioritized_gas_estimate is None

    def test_from_json_coerces_strings(self):
        raw = {
            "gas_estimate": "100",
            "deprioritized_gas_estimate": "50",
            "prioritized_gas_estimate": "200",
        }
        est = GasEstimate.from_json(raw)
        assert est.gas_estimate == 100
        assert est.deprioritized_gas_estimate == 50


# ---------------------------------------------------------------------------
# Transaction
# ---------------------------------------------------------------------------


class TestTransaction:
    def test_from_json_user_transaction(self):
        raw = {
            "hash": "0xabc",
            "type": "user_transaction",
            "version": "123",
            "success": True,
            "vm_status": "Executed successfully",
            "sender": "0x1",
            "sequence_number": "5",
            "payload": {"function": "0x1::coin::transfer"},
            "events": [{"type": "0x1::coin::WithdrawEvent"}],
        }
        txn = Transaction.from_json(raw)
        assert txn.hash == "0xabc"
        assert txn.type == "user_transaction"
        assert txn.version == 123
        assert txn.success is True
        assert txn.vm_status == "Executed successfully"
        assert txn.sender == "0x1"
        assert txn.sequence_number == 5
        assert len(txn.events) == 1

    def test_from_json_pending_transaction(self):
        raw = {
            "hash": "0xdef",
            "type": "pending_transaction",
            "sender": "0x1",
            "sequence_number": "0",
        }
        txn = Transaction.from_json(raw)
        assert txn.version is None
        assert txn.success is None
        assert txn.is_pending

    def test_is_pending_false_for_committed(self):
        raw = {
            "hash": "0xabc",
            "type": "user_transaction",
            "version": "1",
            "success": True,
        }
        txn = Transaction.from_json(raw)
        assert not txn.is_pending

    def test_from_json_no_events(self):
        raw = {"hash": "0xabc", "type": "genesis_transaction"}
        txn = Transaction.from_json(raw)
        assert txn.events == []


# ---------------------------------------------------------------------------
# RestClient — _raise_for_status
# ---------------------------------------------------------------------------


class TestRaiseForStatus:
    def _client(self) -> RestClient:
        return RestClient("https://fullnode.test/v1")

    def test_success_does_not_raise(self):
        client = self._client()
        resp = _json_response({"ok": True}, 200)
        client._raise_for_status(resp)  # Should not raise

    def test_400_raises_bad_request(self):
        client = self._client()
        resp = _json_response({"message": "bad"}, 400)
        with pytest.raises(BadRequestError):
            client._raise_for_status(resp)

    def test_400_with_vm_error_raises_vm_error(self):
        client = self._client()
        resp = _json_response(
            {"message": "vm fail", "vm_error_code": 4001, "error_code": "VM_FAIL"},
            400,
        )
        with pytest.raises(VmError) as exc_info:
            client._raise_for_status(resp)
        assert exc_info.value.vm_error_code == 4001

    def test_400_with_abort_code_in_data(self):
        client = self._client()
        resp = _json_response(
            {"message": "abort", "data": {"abort_code": 42}},
            400,
        )
        # abort_code in data is extracted as vm_error_code → VmError
        with pytest.raises(VmError) as exc_info:
            client._raise_for_status(resp)
        assert exc_info.value.vm_error_code == 42

    def test_404_raises_not_found(self):
        client = self._client()
        resp = _json_response({"message": "not found"}, 404)
        with pytest.raises(NotFoundError):
            client._raise_for_status(resp)

    def test_409_raises_conflict(self):
        client = self._client()
        resp = _json_response({"message": "conflict"}, 409)
        with pytest.raises(ConflictError):
            client._raise_for_status(resp)

    def test_429_raises_rate_limited(self):
        client = self._client()
        resp = _json_response({"message": "slow down"}, 429)
        with pytest.raises(RateLimitedError):
            client._raise_for_status(resp)

    def test_500_raises_internal_server(self):
        client = self._client()
        resp = _json_response({"message": "server error"}, 500)
        with pytest.raises(InternalServerError):
            client._raise_for_status(resp)

    def test_502_raises_internal_server(self):
        client = self._client()
        resp = _json_response({"message": "bad gateway"}, 502)
        with pytest.raises(InternalServerError):
            client._raise_for_status(resp)

    def test_418_raises_api_error(self):
        client = self._client()
        resp = _json_response({"message": "teapot"}, 418)
        with pytest.raises(ApiError):
            client._raise_for_status(resp)

    def test_non_json_body_uses_text(self):
        client = self._client()
        resp = _text_response("plain text error", 500)
        with pytest.raises(InternalServerError, match="plain text error"):
            client._raise_for_status(resp)

    def test_error_code_extracted(self):
        client = self._client()
        resp = _json_response(
            {"message": "not found", "error_code": "ACCOUNT_NOT_FOUND"}, 404
        )
        with pytest.raises(NotFoundError) as exc_info:
            client._raise_for_status(resp)
        assert exc_info.value.error_code == "ACCOUNT_NOT_FOUND"

    def test_301_does_not_raise(self):
        client = self._client()
        resp = _json_response({}, 301)
        client._raise_for_status(resp)  # 3xx should not raise


# ---------------------------------------------------------------------------
# RestClient — constructor
# ---------------------------------------------------------------------------


class TestRestClientConstructor:
    def test_strips_trailing_slash(self):
        client = RestClient("https://example.com/v1/")
        assert client.base_url == "https://example.com/v1"

    def test_api_key_sets_auth_header(self):
        client = RestClient("https://example.com/v1", api_key="my-key")
        assert client._client.headers["authorization"] == "Bearer my-key"

    def test_no_api_key_no_auth_header(self):
        client = RestClient("https://example.com/v1")
        assert "authorization" not in client._client.headers

    def test_chain_id_initially_none(self):
        client = RestClient("https://example.com/v1")
        assert client._chain_id is None


# ---------------------------------------------------------------------------
# RestClient — async context manager
# ---------------------------------------------------------------------------


class TestRestClientContextManager:
    async def test_aenter_returns_self(self):
        client = RestClient("https://example.com/v1")
        async with client as c:
            assert c is client

    async def test_aexit_closes_client(self):
        client = RestClient("https://example.com/v1")
        client._client = AsyncMock()
        async with client:
            pass
        client._client.aclose.assert_called_once()


# ---------------------------------------------------------------------------
# RestClient — get_ledger_info
# ---------------------------------------------------------------------------


class TestGetLedgerInfo:
    async def test_returns_ledger_info(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(SAMPLE_LEDGER_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        info = await client.get_ledger_info()
        assert isinstance(info, LedgerInfo)
        assert info.chain_id == 4

    async def test_raises_on_error(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "error"}, 500)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        with pytest.raises(InternalServerError):
            await client.get_ledger_info()


# ---------------------------------------------------------------------------
# RestClient — chain_id (cached)
# ---------------------------------------------------------------------------


class TestChainId:
    async def test_caches_chain_id(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(SAMPLE_LEDGER_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        cid1 = await client.chain_id()
        cid2 = await client.chain_id()
        assert cid1 == cid2 == 4
        # Only one HTTP call should have been made (caching)
        assert client._client.get.call_count == 1


# ---------------------------------------------------------------------------
# RestClient — get_account
# ---------------------------------------------------------------------------


class TestGetAccount:
    async def test_returns_account_info(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        info = await client.get_account(AccountAddress.ONE)
        assert isinstance(info, AccountInfo)
        assert info.sequence_number == 42

    async def test_not_found_raises(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(
            {"message": "Account not found", "error_code": "ACCOUNT_NOT_FOUND"}, 404
        )
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        with pytest.raises(NotFoundError):
            await client.get_account(AccountAddress.ONE)


# ---------------------------------------------------------------------------
# RestClient — account_sequence_number
# ---------------------------------------------------------------------------


class TestAccountSequenceNumber:
    async def test_returns_sequence_number(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        seq = await client.account_sequence_number(AccountAddress.ONE)
        assert seq == 42

    async def test_returns_zero_for_not_found(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "not found"}, 404)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        seq = await client.account_sequence_number(AccountAddress.ONE)
        assert seq == 0


# ---------------------------------------------------------------------------
# RestClient — get_account_resources
# ---------------------------------------------------------------------------


class TestGetAccountResources:
    async def test_returns_resources_list(self):
        client = RestClient("https://test/v1")
        raw = [
            {
                "type": "0x1::account::Account",
                "data": {"sequence_number": "0"},
            },
            {
                "type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                "data": {"coin": {"value": "100"}},
            },
        ]
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        resources = await client.get_account_resources(AccountAddress.ONE)
        assert len(resources) == 2
        assert all(isinstance(r, Resource) for r in resources)


# ---------------------------------------------------------------------------
# RestClient — get_account_resource
# ---------------------------------------------------------------------------


class TestGetAccountResource:
    async def test_returns_single_resource(self):
        client = RestClient("https://test/v1")
        raw = {
            "type": "0x1::account::Account",
            "data": {"sequence_number": "10"},
        }
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        resource = await client.get_account_resource(
            AccountAddress.ONE, "0x1::account::Account"
        )
        assert isinstance(resource, Resource)
        assert resource.data["sequence_number"] == "10"


# ---------------------------------------------------------------------------
# RestClient — get_transaction_by_hash
# ---------------------------------------------------------------------------


class TestGetTransactionByHash:
    async def test_returns_transaction(self):
        client = RestClient("https://test/v1")
        raw = {
            "hash": "0xabc",
            "type": "user_transaction",
            "version": "1",
            "success": True,
        }
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        txn = await client.get_transaction_by_hash("0xabc")
        assert isinstance(txn, Transaction)
        assert txn.hash == "0xabc"


# ---------------------------------------------------------------------------
# RestClient — get_transaction_by_version
# ---------------------------------------------------------------------------


class TestGetTransactionByVersion:
    async def test_returns_transaction(self):
        client = RestClient("https://test/v1")
        raw = {
            "hash": "0xdef",
            "type": "user_transaction",
            "version": "42",
            "success": True,
        }
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        txn = await client.get_transaction_by_version(42)
        assert isinstance(txn, Transaction)
        assert txn.version == 42


# ---------------------------------------------------------------------------
# RestClient — get_account_transactions
# ---------------------------------------------------------------------------


class TestGetAccountTransactions:
    async def test_returns_transaction_list(self):
        client = RestClient("https://test/v1")
        raw = [
            {"hash": "0x1", "type": "user_transaction", "version": "1"},
            {"hash": "0x2", "type": "user_transaction", "version": "2"},
        ]
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        txns = await client.get_account_transactions(AccountAddress.ONE)
        assert len(txns) == 2
        assert all(isinstance(t, Transaction) for t in txns)


# ---------------------------------------------------------------------------
# RestClient — estimate_gas_price
# ---------------------------------------------------------------------------


class TestEstimateGasPrice:
    async def test_returns_gas_estimate(self):
        client = RestClient("https://test/v1")
        raw = {
            "gas_estimate": 100,
            "deprioritized_gas_estimate": 50,
            "prioritized_gas_estimate": 200,
        }
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        est = await client.estimate_gas_price()
        assert isinstance(est, GasEstimate)
        assert est.gas_estimate == 100


# ---------------------------------------------------------------------------
# RestClient — submit_bcs_transaction
# ---------------------------------------------------------------------------


class TestSubmitBcsTransaction:
    async def test_returns_hash(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"hash": "0xdeadbeef"})
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        from aptos_sdk.bcs import Serializer
        from aptos_sdk.ed25519 import Ed25519PrivateKey
        from aptos_sdk.transactions import (
            EntryFunction,
            RawTransaction,
            SignedTransaction,
            TransactionPayload,
        )

        priv = Ed25519PrivateKey.generate()
        sender = AccountAddress.from_hex("0x" + "ab" * 32)
        # Encode args properly using TransactionArgument
        from aptos_sdk.transactions import TransactionArgument

        ef = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(AccountAddress.ONE, Serializer.struct),
                TransactionArgument(100, Serializer.u64),
            ],
        )
        payload = TransactionPayload(ef)
        raw = RawTransaction(sender, 0, payload, 200_000, 100, 9_999_999_999, 4)
        auth = raw.sign(priv)
        signed = SignedTransaction(raw, auth)

        txn_hash = await client.submit_bcs_transaction(signed)
        assert txn_hash == "0xdeadbeef"


# ---------------------------------------------------------------------------
# RestClient — wait_for_transaction
# ---------------------------------------------------------------------------


class TestWaitForTransaction:
    async def test_returns_committed_transaction(self):
        client = RestClient("https://test/v1")
        committed = _json_response(
            {
                "hash": "0xabc",
                "type": "user_transaction",
                "version": "1",
                "success": True,
            }
        )
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=committed)

        txn = await client.wait_for_transaction("0xabc", timeout_secs=5)
        assert isinstance(txn, Transaction)
        assert txn.success is True

    async def test_polls_until_committed(self):
        client = RestClient("https://test/v1")
        pending = _json_response(
            {"hash": "0xabc", "type": "pending_transaction", "sender": "0x1"}
        )
        committed = _json_response(
            {
                "hash": "0xabc",
                "type": "user_transaction",
                "version": "1",
                "success": True,
            }
        )
        call_count = 0

        async def mock_get(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return pending
            return committed

        client._client = AsyncMock()
        client._client.get = mock_get

        # Patch sleep to avoid actual waiting
        with patch("aptos_sdk.async_client.asyncio.sleep", new_callable=AsyncMock):
            txn = await client.wait_for_transaction("0xabc", timeout_secs=30)
        assert txn.success is True
        assert call_count == 3

    async def test_timeout_raises(self):
        client = RestClient("https://test/v1")
        not_found = _json_response({"message": "not found"}, 404)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=not_found)

        # Use tiny timeout; patch sleep to resolve instantly
        with patch("aptos_sdk.async_client.asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "aptos_sdk.async_client.time.monotonic",
                side_effect=[
                    0,
                    0,
                    100,
                ],  # start, first check (ok), second check (expired)
            ):
                with pytest.raises(AptosTimeoutError):
                    await client.wait_for_transaction("0xabc", timeout_secs=5)

    async def test_network_error_retries_until_timeout(self):
        client = RestClient("https://test/v1")

        async def mock_get(**kwargs):
            raise httpx.ConnectError("connection refused")

        client._client = AsyncMock()
        client._client.get = mock_get

        with patch("aptos_sdk.async_client.asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "aptos_sdk.async_client.time.monotonic",
                side_effect=[0, 100],  # start, then expired
            ):
                with pytest.raises(AptosTimeoutError, match="network error"):
                    await client.wait_for_transaction("0xabc", timeout_secs=5)


# ---------------------------------------------------------------------------
# RestClient — view_function
# ---------------------------------------------------------------------------


class TestViewFunction:
    async def test_returns_list(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(["12345"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        result = await client.view_function(
            "0x1::coin", "balance", ["0x1::aptos_coin::AptosCoin"], ["0x1"]
        )
        assert result == ["12345"]

    async def test_wraps_non_list_in_list(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response("single_value")
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        result = await client.view_function("0x1::foo", "bar", [], [])
        assert result == ["single_value"]


# ---------------------------------------------------------------------------
# RestClient — get_table_item
# ---------------------------------------------------------------------------


class TestGetTableItem:
    async def test_returns_value(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"amount": "999"})
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        result = await client.get_table_item("0xhandle", "address", "u128", "0x1")
        assert result == {"amount": "999"}


# ---------------------------------------------------------------------------
# RestClient — legacy aliases
# ---------------------------------------------------------------------------


class TestLegacyAliases:
    async def test_info_returns_dict(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(SAMPLE_LEDGER_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.info()
        assert isinstance(result, dict)
        assert result["chain_id"] == 4

    async def test_account_returns_dict(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.account(AccountAddress.ONE)
        assert isinstance(result, dict)

    async def test_transaction_pending_true_on_404(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "not found"}, 404)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.transaction_pending("0xabc")
        assert result is True

    async def test_transaction_pending_true_when_pending(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"hash": "0xabc", "type": "pending_transaction"})
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.transaction_pending("0xabc")
        assert result is True

    async def test_transaction_pending_false_when_committed(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(
            {"hash": "0xabc", "type": "user_transaction", "version": "1"}
        )
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.transaction_pending("0xabc")
        assert result is False

    async def test_current_timestamp(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response(SAMPLE_LEDGER_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        ts = await client.current_timestamp()
        assert ts == 1_700_000_000_000_000 / 1_000_000


# ---------------------------------------------------------------------------
# FaucetClient
# ---------------------------------------------------------------------------


class TestFaucetClient:
    def test_constructor_strips_trailing_slash(self):
        rest = RestClient("https://test/v1")
        faucet = FaucetClient("https://faucet.test/", rest)
        assert faucet.base_url == "https://faucet.test"

    async def test_fund_account_returns_hash(self):
        rest = RestClient("https://test/v1")
        # Mock the internal httpx client used by rest_client
        mock_post_resp = _json_response(["0xtxnhash"])
        # Also mock wait_for_transaction
        committed = _json_response(
            {
                "hash": "0xtxnhash",
                "type": "user_transaction",
                "version": "1",
                "success": True,
            }
        )
        rest._client = AsyncMock()
        rest._client.post = AsyncMock(return_value=mock_post_resp)
        rest._client.get = AsyncMock(return_value=committed)

        faucet = FaucetClient("https://faucet.test", rest)
        txn_hash = await faucet.fund_account(AccountAddress.ONE, 100_000_000)
        assert txn_hash == "0xtxnhash"

    async def test_fund_account_no_wait(self):
        rest = RestClient("https://test/v1")
        mock_post_resp = _json_response(["0xhash123"])
        rest._client = AsyncMock()
        rest._client.post = AsyncMock(return_value=mock_post_resp)

        faucet = FaucetClient("https://faucet.test", rest)
        txn_hash = await faucet.fund_account(
            AccountAddress.ONE, 100, wait_for_transaction=False
        )
        assert txn_hash == "0xhash123"
        # get should NOT have been called (no wait)
        rest._client.get.assert_not_called()

    async def test_fund_account_error_raises(self):
        rest = RestClient("https://test/v1")
        mock_post_resp = _text_response("Faucet error", 500)
        rest._client = AsyncMock()
        rest._client.post = AsyncMock(return_value=mock_post_resp)

        faucet = FaucetClient("https://faucet.test", rest)
        with pytest.raises(ApiError):
            await faucet.fund_account(
                AccountAddress.ONE, 100, wait_for_transaction=False
            )

    async def test_fund_account_single_hash_string(self):
        rest = RestClient("https://test/v1")
        # Faucet returns a single string instead of a list
        mock_post_resp = _json_response("0xsinglehash")
        rest._client = AsyncMock()
        rest._client.post = AsyncMock(return_value=mock_post_resp)

        faucet = FaucetClient("https://faucet.test", rest)
        txn_hash = await faucet.fund_account(
            AccountAddress.ONE, 100, wait_for_transaction=False
        )
        assert txn_hash == "0xsinglehash"

    async def test_healthy_true(self):
        rest = RestClient("https://test/v1")
        mock_resp = _text_response("tap:ok")
        rest._client = AsyncMock()
        rest._client.get = AsyncMock(return_value=mock_resp)

        faucet = FaucetClient("https://faucet.test", rest)
        assert await faucet.healthy() is True

    async def test_healthy_false(self):
        rest = RestClient("https://test/v1")
        mock_resp = _text_response("not ok")
        rest._client = AsyncMock()
        rest._client.get = AsyncMock(return_value=mock_resp)

        faucet = FaucetClient("https://faucet.test", rest)
        assert await faucet.healthy() is False

    async def test_auth_token_set(self):
        rest = RestClient("https://test/v1")
        faucet = FaucetClient("https://faucet.test", rest, auth_token="secret")
        assert faucet._headers["Authorization"] == "Bearer secret"

    async def test_close_delegates_to_rest_client(self):
        rest = RestClient("https://test/v1")
        rest._client = AsyncMock()
        faucet = FaucetClient("https://faucet.test", rest)
        await faucet.close()
        rest._client.aclose.assert_called_once()


# ---------------------------------------------------------------------------
# RestClient — internal HTTP helpers
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    async def test_get_filters_none_params(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"ok": True})
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        await client._get("test", params={"a": 1, "b": None})
        call_kwargs = client._client.get.call_args
        assert call_kwargs.kwargs["params"] == {"a": 1}

    async def test_post_json_body(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"ok": True})
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        await client._post("test", data={"key": "value"})
        call_kwargs = client._client.post.call_args
        assert call_kwargs.kwargs["json"] == {"key": "value"}

    async def test_post_bytes_body(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"ok": True})
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        await client._post("test", content=b"\x01\x02")
        call_kwargs = client._client.post.call_args
        assert call_kwargs.kwargs["content"] == b"\x01\x02"
        assert "json" not in call_kwargs.kwargs

    async def test_get_no_params(self):
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"ok": True})
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        await client._get("endpoint")
        call_kwargs = client._client.get.call_args
        assert call_kwargs.kwargs["params"] == {}
