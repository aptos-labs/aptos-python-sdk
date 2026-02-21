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
        assert resp.status_code == 200

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
        assert resp.status_code == 301


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


# ---------------------------------------------------------------------------
# Shared test helpers for account-based tests
# ---------------------------------------------------------------------------


def _make_account():  # type: ignore[no-untyped-def]
    """Create a deterministic test Account with a generated key."""
    from aptos_sdk.account import Account
    from aptos_sdk.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    address = AccountAddress.from_hex("0x" + "ab" * 32)
    return Account(address, priv)  # type: ignore[arg-type]


def _make_transfer_payload():  # type: ignore[no-untyped-def]
    """Build a simple transfer TransactionPayload for use in tests."""
    from aptos_sdk.bcs import Serializer
    from aptos_sdk.transactions import (
        EntryFunction,
        TransactionArgument,
        TransactionPayload,
    )

    ef = EntryFunction.natural(
        "0x1::aptos_account",
        "transfer",
        [],
        [
            TransactionArgument(AccountAddress.ONE, Serializer.struct),
            TransactionArgument(100, Serializer.u64),
        ],
    )
    return TransactionPayload(ef)


# ---------------------------------------------------------------------------
# RestClient — account_balance (lines 739-747)
# ---------------------------------------------------------------------------


class TestAccountBalance:
    async def test_returns_balance_for_default_coin(self):
        """account_balance calls view_bcs_payload and returns int(result[0])."""
        client = RestClient("https://test/v1")
        # view_bcs_payload posts directly to _client.post
        mock_resp = _json_response(["50000"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        balance = await client.account_balance(AccountAddress.ONE)
        assert balance == 50_000
        assert isinstance(balance, int)

    async def test_returns_balance_for_custom_coin(self):
        """account_balance passes the coin_type as a TypeTag to view_bcs_payload."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response(["999"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        balance = await client.account_balance(
            AccountAddress.ONE,
            coin_type="0x1::aptos_coin::AptosCoin",
        )
        assert balance == 999

    async def test_balance_with_ledger_version(self):
        """account_balance appends ledger_version to the URL when provided."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response(["12345"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        balance = await client.account_balance(
            AccountAddress.ONE, ledger_version=500000
        )
        assert balance == 12345
        # The URL passed to post should contain the ledger_version query param.
        call_args = client._client.post.call_args
        assert "ledger_version=500000" in call_args[0][0]

    async def test_balance_raises_on_error(self):
        """account_balance propagates HTTP errors from view_bcs_payload."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "not found"}, 404)
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        from aptos_sdk.errors import NotFoundError

        with pytest.raises(NotFoundError):
            await client.account_balance(AccountAddress.ONE)


# ---------------------------------------------------------------------------
# RestClient — get_account_modules (lines 809-814)
# ---------------------------------------------------------------------------


class TestGetAccountModules:
    async def test_returns_list_of_modules(self):
        """get_account_modules returns a list of raw module dicts."""
        client = RestClient("https://test/v1")
        raw = [
            {"abi": {"name": "coin"}, "bytecode": "0xdeadbeef"},
            {"abi": {"name": "token"}, "bytecode": "0xcafebabe"},
        ]
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        modules = await client.get_account_modules(AccountAddress.ONE)
        assert len(modules) == 2
        assert modules[0]["abi"]["name"] == "coin"

    async def test_returns_empty_list(self):
        """get_account_modules returns an empty list when no modules exist."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response([])
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        modules = await client.get_account_modules(AccountAddress.ONE)
        assert modules == []

    async def test_raises_on_not_found(self):
        """get_account_modules propagates 404 as NotFoundError."""
        from aptos_sdk.errors import NotFoundError

        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "Account not found"}, 404)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        with pytest.raises(NotFoundError):
            await client.get_account_modules(AccountAddress.ONE)

    async def test_passes_ledger_version_param(self):
        """get_account_modules forwards ledger_version to the query string."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response([])
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        await client.get_account_modules(AccountAddress.ONE, ledger_version=999)
        call_kwargs = client._client.get.call_args
        assert call_kwargs.kwargs["params"] == {"ledger_version": 999}


# ---------------------------------------------------------------------------
# RestClient — get_account_module (lines 846-851)
# ---------------------------------------------------------------------------


class TestGetAccountModule:
    async def test_returns_single_module(self):
        """get_account_module returns the raw module dict for a named module."""
        client = RestClient("https://test/v1")
        raw = {"abi": {"name": "coin"}, "bytecode": "0xdeadbeef"}
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        module = await client.get_account_module(AccountAddress.ONE, "coin")
        assert module["abi"]["name"] == "coin"
        assert module["bytecode"] == "0xdeadbeef"

    async def test_raises_on_not_found(self):
        """get_account_module propagates 404 for unknown modules."""
        from aptos_sdk.errors import NotFoundError

        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "module not found"}, 404)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        with pytest.raises(NotFoundError):
            await client.get_account_module(AccountAddress.ONE, "nonexistent")

    async def test_endpoint_contains_module_name(self):
        """get_account_module constructs the URL with the module name."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response({"abi": {}, "bytecode": ""})
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        await client.get_account_module(AccountAddress.ONE, "my_module")
        call_args = client._client.get.call_args
        assert "my_module" in call_args.kwargs["url"]


# ---------------------------------------------------------------------------
# RestClient — create_bcs_transaction (lines 970-988)
# ---------------------------------------------------------------------------


class TestCreateBcsTransaction:
    async def test_with_account_object_fetches_address(self):
        """create_bcs_transaction with Account extracts sender.address."""
        from aptos_sdk.transactions import RawTransaction

        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        # Mock account_sequence_number — called internally
        mock_acct_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_acct_resp)

        raw_txn = await client.create_bcs_transaction(account, payload)
        assert isinstance(raw_txn, RawTransaction)
        assert raw_txn.sender == account.address

    async def test_with_account_address_uses_directly(self):
        """create_bcs_transaction with AccountAddress uses it directly as sender."""
        from aptos_sdk.transactions import RawTransaction

        sender_address = AccountAddress.from_hex("0x" + "cd" * 32)
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        mock_acct_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_acct_resp)

        raw_txn = await client.create_bcs_transaction(sender_address, payload)
        assert isinstance(raw_txn, RawTransaction)
        assert raw_txn.sender == sender_address

    async def test_auto_fetches_sequence_number_when_none(self):
        """create_bcs_transaction fetches sequence_number when not provided."""

        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        mock_acct_resp = _json_response(
            {"sequence_number": "7", "authentication_key": "0x" + "ab" * 32}
        )
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_acct_resp)

        raw_txn = await client.create_bcs_transaction(account, payload)
        assert raw_txn.sequence_number == 7

    async def test_uses_explicit_sequence_number(self):
        """create_bcs_transaction skips network call when sequence_number provided."""

        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        client._client = AsyncMock()
        # get should NOT be called because sequence_number is provided
        client._client.get = AsyncMock(
            side_effect=AssertionError("Should not call get")
        )

        raw_txn = await client.create_bcs_transaction(
            account, payload, sequence_number=99
        )
        assert raw_txn.sequence_number == 99

    async def test_uses_default_gas_values(self):
        """create_bcs_transaction populates max_gas and gas_unit_price with defaults."""
        from aptos_sdk.async_client import (
            _DEFAULT_GAS_UNIT_PRICE,
            _DEFAULT_MAX_GAS_AMOUNT,
        )

        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        mock_acct_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_acct_resp)

        raw_txn = await client.create_bcs_transaction(account, payload)
        assert raw_txn.max_gas_amount == _DEFAULT_MAX_GAS_AMOUNT
        assert raw_txn.gas_unit_price == _DEFAULT_GAS_UNIT_PRICE


# ---------------------------------------------------------------------------
# RestClient — create_bcs_signed_transaction (lines 1012-1014)
# ---------------------------------------------------------------------------


class TestCreateBcsSignedTransaction:
    async def test_returns_signed_transaction(self):
        """create_bcs_signed_transaction returns a SignedTransaction ready for submission."""
        from aptos_sdk.transactions import SignedTransaction

        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        mock_acct_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_acct_resp)

        signed_txn = await client.create_bcs_signed_transaction(account, payload)
        assert isinstance(signed_txn, SignedTransaction)
        # Ensure it can be serialized to bytes (needed for submission).
        assert len(signed_txn.bytes()) > 0

    async def test_with_explicit_sequence_number(self):
        """create_bcs_signed_transaction passes sequence_number through."""
        from aptos_sdk.transactions import SignedTransaction

        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        client._client = AsyncMock()

        signed_txn = await client.create_bcs_signed_transaction(
            account, payload, sequence_number=5
        )
        assert isinstance(signed_txn, SignedTransaction)
        assert signed_txn.transaction.sequence_number == 5


# ---------------------------------------------------------------------------
# RestClient — create_multi_agent_bcs_transaction (lines 1042-1075)
# ---------------------------------------------------------------------------


class TestCreateMultiAgentBcsTransaction:
    async def test_returns_signed_transaction_with_multiple_signers(self):
        """create_multi_agent_bcs_transaction signs with both sender and secondary."""
        from aptos_sdk.account import Account
        from aptos_sdk.ed25519 import Ed25519PrivateKey
        from aptos_sdk.transactions import SignedTransaction

        sender = _make_account()
        secondary = Account(
            AccountAddress.from_hex("0x" + "cd" * 32),
            Ed25519PrivateKey.generate(),
        )
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        mock_acct_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_acct_resp)

        signed_txn = await client.create_multi_agent_bcs_transaction(
            sender, [secondary], payload
        )
        assert isinstance(signed_txn, SignedTransaction)
        # Verify the raw bytes can be serialized.
        assert len(signed_txn.bytes()) > 0

    async def test_empty_secondary_accounts(self):
        """create_multi_agent_bcs_transaction works with no secondary accounts."""
        from aptos_sdk.transactions import SignedTransaction

        sender = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        mock_acct_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_acct_resp)

        signed_txn = await client.create_multi_agent_bcs_transaction(
            sender, [], payload
        )
        assert isinstance(signed_txn, SignedTransaction)

    async def test_fetches_sequence_number_from_chain(self):
        """create_multi_agent_bcs_transaction auto-fetches the sequence number."""

        sender = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4
        mock_resp = _json_response(
            {"sequence_number": "3", "authentication_key": "0x" + "ab" * 32}
        )
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        signed_txn = await client.create_multi_agent_bcs_transaction(
            sender, [], payload
        )
        assert signed_txn.transaction.sequence_number == 3


# ---------------------------------------------------------------------------
# RestClient — submit_transaction (lines 1143-1144)
# ---------------------------------------------------------------------------


class TestSubmitTransaction:
    async def test_builds_signs_and_submits(self):
        """submit_transaction delegates to create_bcs_signed_transaction and submit_bcs_transaction."""
        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        # GET for sequence number, POST for submission
        get_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        post_resp = _json_response({"hash": "0xsubmitted"})

        async def mock_get(**kwargs):
            return get_resp

        async def mock_post(**kwargs):
            return post_resp

        client._client = AsyncMock()
        client._client.get = mock_get
        client._client.post = mock_post

        txn_hash = await client.submit_transaction(account, payload)
        assert txn_hash == "0xsubmitted"

    async def test_propagates_error_on_failed_submission(self):
        """submit_transaction raises ApiError when submission returns an error."""
        from aptos_sdk.errors import BadRequestError

        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        get_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        post_resp = _json_response({"message": "bad txn"}, 400)

        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=get_resp)
        client._client.post = AsyncMock(return_value=post_resp)

        with pytest.raises(BadRequestError):
            await client.submit_transaction(account, payload)


# ---------------------------------------------------------------------------
# RestClient — wait_for_transaction: network error sleep+continue, pending
# timeout (lines 1187-1188, 1205)
# ---------------------------------------------------------------------------


class TestWaitForTransactionEdgeCases:
    async def test_network_error_sleeps_and_retries_within_timeout(self):
        """A transient network error within deadline causes a sleep and retry."""
        client = RestClient("https://test/v1")

        call_count = 0

        async def mock_get(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("transient failure")
            # Second call succeeds with a committed transaction.
            return _json_response(
                {
                    "hash": "0xabc",
                    "type": "user_transaction",
                    "version": "1",
                    "success": True,
                }
            )

        client._client = AsyncMock()
        client._client.get = mock_get

        with patch(
            "aptos_sdk.async_client.asyncio.sleep", new_callable=AsyncMock
        ) as mock_sleep:
            with patch(
                "aptos_sdk.async_client.time.monotonic",
                side_effect=[0, 0, 30],  # start, after error check (ok), committed
            ):
                txn = await client.wait_for_transaction("0xabc", timeout_secs=60)

        assert txn.success is True
        # sleep must have been called for the retry after the network error
        mock_sleep.assert_called()

    async def test_pending_transaction_times_out(self):
        """A transaction stuck in pending state triggers AptosTimeoutError."""
        client = RestClient("https://test/v1")

        async def mock_get(**kwargs):
            return _json_response(
                {"hash": "0xabc", "type": "pending_transaction", "sender": "0x1"}
            )

        client._client = AsyncMock()
        client._client.get = mock_get

        with patch("aptos_sdk.async_client.asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "aptos_sdk.async_client.time.monotonic",
                side_effect=[
                    0,  # deadline = 0 + 5 = 5
                    100,  # first pending check: 100 >= 5, should timeout
                ],
            ):
                with pytest.raises(AptosTimeoutError, match="still pending"):
                    await client.wait_for_transaction("0xabc", timeout_secs=5)

    async def test_404_within_deadline_sleeps_and_retries(self):
        """A 404 within deadline sleeps and continues polling."""
        client = RestClient("https://test/v1")

        call_count = 0

        async def mock_get(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return _json_response({"message": "not found"}, 404)
            return _json_response(
                {
                    "hash": "0xabc",
                    "type": "user_transaction",
                    "version": "1",
                    "success": True,
                }
            )

        client._client = AsyncMock()
        client._client.get = mock_get

        with patch("aptos_sdk.async_client.asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "aptos_sdk.async_client.time.monotonic",
                side_effect=[0, 0, 0, 0, 30],  # start + multiple checks within timeout
            ):
                txn = await client.wait_for_transaction("0xabc", timeout_secs=60)

        assert txn.success is True
        assert call_count == 3


# ---------------------------------------------------------------------------
# RestClient — simulate_transaction (lines 1245-1246)
# ---------------------------------------------------------------------------


class TestSimulateTransaction:
    async def test_returns_simulation_result(self):
        """simulate_transaction builds a zero-signature tx and calls simulate_bcs_transaction."""
        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        sim_result = [
            {"gas_used": "500", "success": True, "vm_status": "Executed successfully"}
        ]
        post_resp = _json_response(sim_result)
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=post_resp)

        from aptos_sdk.chain_id import ChainId
        from aptos_sdk.transactions import RawTransaction

        raw_txn = RawTransaction(
            account.address,
            0,
            payload,
            100_000,
            100,
            9_999_999_999,
            ChainId(4),
        )

        result = await client.simulate_transaction(raw_txn, account)
        assert result == sim_result

    async def test_with_estimate_gas_passes_params(self):
        """simulate_transaction with estimate_gas=True passes gas estimation params."""
        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        sim_result = [{"gas_used": "300", "success": True}]
        post_resp = _json_response(sim_result)
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=post_resp)

        from aptos_sdk.chain_id import ChainId
        from aptos_sdk.transactions import RawTransaction

        raw_txn = RawTransaction(
            account.address,
            0,
            payload,
            100_000,
            100,
            9_999_999_999,
            ChainId(4),
        )

        result = await client.simulate_transaction(raw_txn, account, estimate_gas=True)
        assert result == sim_result

        call_kwargs = client._client.post.call_args
        assert (
            "estimate_gas_unit_price=true" in call_kwargs.kwargs["url"]
            or call_kwargs.kwargs.get("params", {}).get("estimate_gas_unit_price")
            == "true"
        )


# ---------------------------------------------------------------------------
# RestClient — view_bcs_payload (lines 1347-1361)
# ---------------------------------------------------------------------------


class TestViewBcsPayload:
    async def test_returns_json_response(self):
        """view_bcs_payload posts BCS content and returns the JSON result."""
        from aptos_sdk.bcs import Serializer
        from aptos_sdk.transactions import TransactionArgument
        from aptos_sdk.type_tag import StructTag, TypeTag

        client = RestClient("https://test/v1")
        mock_resp = _json_response(["12345"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        result = await client.view_bcs_payload(
            "0x1::coin",
            "balance",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [TransactionArgument(AccountAddress.ONE, Serializer.struct)],
        )
        assert result == ["12345"]

    async def test_with_ledger_version_appends_to_url(self):
        """view_bcs_payload appends ledger_version to the URL as a query param."""
        from aptos_sdk.bcs import Serializer
        from aptos_sdk.transactions import TransactionArgument
        from aptos_sdk.type_tag import StructTag, TypeTag

        client = RestClient("https://test/v1")
        mock_resp = _json_response(["99"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        await client.view_bcs_payload(
            "0x1::coin",
            "balance",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [TransactionArgument(AccountAddress.ONE, Serializer.struct)],
            ledger_version=12345,
        )
        call_args = client._client.post.call_args
        assert "ledger_version=12345" in call_args[0][0]

    async def test_raises_on_error_response(self):
        """view_bcs_payload propagates HTTP errors."""
        from aptos_sdk.bcs import Serializer
        from aptos_sdk.errors import NotFoundError
        from aptos_sdk.transactions import TransactionArgument
        from aptos_sdk.type_tag import StructTag, TypeTag

        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "not found"}, 404)
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        with pytest.raises(NotFoundError):
            await client.view_bcs_payload(
                "0x1::coin",
                "balance",
                [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
                [TransactionArgument(AccountAddress.ONE, Serializer.struct)],
            )

    async def test_uses_bcs_content_type_header(self):
        """view_bcs_payload sends the correct BCS content-type header."""
        from aptos_sdk.bcs import Serializer
        from aptos_sdk.transactions import TransactionArgument
        from aptos_sdk.type_tag import StructTag, TypeTag

        client = RestClient("https://test/v1")
        mock_resp = _json_response(["0"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        await client.view_bcs_payload(
            "0x1::coin",
            "balance",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [TransactionArgument(AccountAddress.ONE, Serializer.struct)],
        )
        call_kwargs = client._client.post.call_args
        assert (
            call_kwargs.kwargs["headers"]["Content-Type"]
            == "application/x.aptos.view_function+bcs"
        )


# ---------------------------------------------------------------------------
# RestClient — simulate_bcs_transaction (lines 1420-1434)
# ---------------------------------------------------------------------------


class TestSimulateBcsTransaction:
    def _make_signed_txn(self):
        """Build a minimal SignedTransaction for simulation tests."""
        from aptos_sdk.chain_id import ChainId
        from aptos_sdk.transactions import RawTransaction, SignedTransaction

        account = _make_account()
        payload = _make_transfer_payload()
        raw_txn = RawTransaction(
            account.address,
            0,
            payload,
            100_000,
            100,
            9_999_999_999,
            ChainId(4),
        )
        priv = account.private_key
        auth = raw_txn.sign(priv)
        return SignedTransaction(raw_txn, auth)

    async def test_returns_simulation_dict(self):
        """simulate_bcs_transaction posts BCS bytes and returns the JSON result."""
        client = RestClient("https://test/v1")
        sim_result = [
            {"gas_used": "1000", "success": True, "vm_status": "Executed successfully"}
        ]
        mock_resp = _json_response(sim_result)
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        signed_txn = self._make_signed_txn()
        result = await client.simulate_bcs_transaction(signed_txn)
        assert result == sim_result

    async def test_without_estimate_gas_no_params(self):
        """simulate_bcs_transaction sends no gas estimation params by default."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response([{"success": True}])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        signed_txn = self._make_signed_txn()
        await client.simulate_bcs_transaction(signed_txn, estimate_gas=False)

        call_kwargs = client._client.post.call_args
        params = call_kwargs.kwargs.get("params", {})
        assert "estimate_gas_unit_price" not in params

    async def test_with_estimate_gas_sends_params(self):
        """simulate_bcs_transaction with estimate_gas=True includes gas params."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response([{"success": True}])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        signed_txn = self._make_signed_txn()
        await client.simulate_bcs_transaction(signed_txn, estimate_gas=True)

        call_kwargs = client._client.post.call_args
        params = call_kwargs.kwargs.get("params", {})
        assert params.get("estimate_gas_unit_price") == "true"
        assert params.get("estimate_max_gas_amount") == "true"

    async def test_raises_on_api_error(self):
        """simulate_bcs_transaction propagates non-success HTTP errors."""
        from aptos_sdk.errors import BadRequestError

        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "invalid signature"}, 400)
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        signed_txn = self._make_signed_txn()
        with pytest.raises(BadRequestError):
            await client.simulate_bcs_transaction(signed_txn)


# ---------------------------------------------------------------------------
# RestClient — bcs_transfer (lines 1555-1569)
# ---------------------------------------------------------------------------


class TestBcsTransfer:
    async def test_returns_transaction_hash(self):
        """bcs_transfer builds the transfer payload and returns the submitted hash."""
        account = _make_account()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        get_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        post_resp = _json_response({"hash": "0xtransfer"})

        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=get_resp)
        client._client.post = AsyncMock(return_value=post_resp)

        txn_hash = await client.bcs_transfer(account, AccountAddress.ONE, 500_000)
        assert txn_hash == "0xtransfer"

    async def test_with_explicit_sequence_number(self):
        """bcs_transfer passes sequence_number through to avoid fetching it."""
        account = _make_account()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        post_resp = _json_response({"hash": "0xtransfer2"})
        client._client = AsyncMock()
        # get should NOT be called when sequence_number is provided
        client._client.get = AsyncMock(side_effect=AssertionError("Should not GET"))
        client._client.post = AsyncMock(return_value=post_resp)

        txn_hash = await client.bcs_transfer(
            account, AccountAddress.ONE, 1_000, sequence_number=5
        )
        assert txn_hash == "0xtransfer2"

    async def test_raises_on_submission_error(self):
        """bcs_transfer propagates submission errors."""
        from aptos_sdk.errors import ConflictError

        account = _make_account()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        get_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        post_resp = _json_response({"message": "duplicate txn"}, 409)

        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=get_resp)
        client._client.post = AsyncMock(return_value=post_resp)

        with pytest.raises(ConflictError):
            await client.bcs_transfer(account, AccountAddress.ONE, 100)


# ---------------------------------------------------------------------------
# RestClient — transfer_coins (lines 1603-1617)
# ---------------------------------------------------------------------------


class TestTransferCoins:
    async def test_returns_transaction_hash(self):
        """transfer_coins builds the generic transfer payload and submits it."""
        account = _make_account()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        get_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        post_resp = _json_response({"hash": "0xcoins"})

        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=get_resp)
        client._client.post = AsyncMock(return_value=post_resp)

        txn_hash = await client.transfer_coins(
            account,
            AccountAddress.ONE,
            "0x1::aptos_coin::AptosCoin",
            250_000,
        )
        assert txn_hash == "0xcoins"

    async def test_with_explicit_sequence_number_skips_fetch(self):
        """transfer_coins with sequence_number skips the GET sequence_number call."""
        account = _make_account()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        post_resp = _json_response({"hash": "0xcoins2"})
        client._client = AsyncMock()
        client._client.get = AsyncMock(side_effect=AssertionError("Should not GET"))
        client._client.post = AsyncMock(return_value=post_resp)

        txn_hash = await client.transfer_coins(
            account,
            AccountAddress.ONE,
            "0x1::aptos_coin::AptosCoin",
            100,
            sequence_number=0,
        )
        assert txn_hash == "0xcoins2"

    async def test_raises_on_submission_error(self):
        """transfer_coins propagates submission errors."""
        from aptos_sdk.errors import BadRequestError

        account = _make_account()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        get_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        post_resp = _json_response({"message": "bad request"}, 400)

        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=get_resp)
        client._client.post = AsyncMock(return_value=post_resp)

        with pytest.raises(BadRequestError):
            await client.transfer_coins(
                account,
                AccountAddress.ONE,
                "0x1::aptos_coin::AptosCoin",
                100,
            )


# ---------------------------------------------------------------------------
# RestClient — legacy alias: account_resource (lines 1666-1669)
# ---------------------------------------------------------------------------


class TestLegacyAccountResource:
    async def test_returns_dict_with_type_and_data(self):
        """account_resource returns a plain dict wrapping the typed Resource."""
        client = RestClient("https://test/v1")
        raw = {
            "type": "0x1::account::Account",
            "data": {"sequence_number": "5"},
        }
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.account_resource(
            AccountAddress.ONE, "0x1::account::Account"
        )
        assert isinstance(result, dict)
        assert result["type"] == "0x1::account::Account"
        assert result["data"]["sequence_number"] == "5"

    async def test_raises_not_found_for_unknown_resource(self):
        """account_resource propagates NotFoundError from get_account_resource."""
        from aptos_sdk.errors import NotFoundError

        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "not found"}, 404)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        with pytest.raises(NotFoundError):
            await client.account_resource(AccountAddress.ONE, "0x1::foo::Bar")


# ---------------------------------------------------------------------------
# RestClient — legacy alias: account_resources (lines 1682-1683)
# ---------------------------------------------------------------------------


class TestLegacyAccountResources:
    async def test_returns_list_of_dicts(self):
        """account_resources returns a list of plain dicts."""
        client = RestClient("https://test/v1")
        raw = [
            {"type": "0x1::account::Account", "data": {"sequence_number": "0"}},
            {"type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>", "data": {}},
        ]
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.account_resources(AccountAddress.ONE)
        assert isinstance(result, list)
        assert len(result) == 2
        assert all(isinstance(r, dict) for r in result)
        assert result[0]["type"] == "0x1::account::Account"


# ---------------------------------------------------------------------------
# RestClient — legacy alias: account_module (line 1697)
# ---------------------------------------------------------------------------


class TestLegacyAccountModule:
    async def test_delegates_to_get_account_module(self):
        """account_module returns the same dict as get_account_module."""
        client = RestClient("https://test/v1")
        raw = {"abi": {"name": "coin"}, "bytecode": "0xbeef"}
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.account_module(AccountAddress.ONE, "coin")
        assert result == raw


# ---------------------------------------------------------------------------
# RestClient — legacy alias: account_modules (lines 1714-1723)
# ---------------------------------------------------------------------------


class TestLegacyAccountModules:
    async def test_returns_list_of_module_dicts(self):
        """account_modules returns a list of raw module dicts."""
        client = RestClient("https://test/v1")
        raw = [
            {"abi": {"name": "coin"}, "bytecode": "0xdeadbeef"},
        ]
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.account_modules(AccountAddress.ONE)
        assert result == raw

    async def test_accepts_limit_and_start_params(self):
        """account_modules forwards limit and start to the query string."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response([])
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        await client.account_modules(AccountAddress.ONE, limit=10, start="abc")
        call_kwargs = client._client.get.call_args
        params = call_kwargs.kwargs["params"]
        assert params["limit"] == 10
        assert params["start"] == "abc"


# ---------------------------------------------------------------------------
# RestClient — legacy alias: transaction_by_hash (lines 1732-1734)
# ---------------------------------------------------------------------------


class TestLegacyTransactionByHash:
    async def test_returns_raw_dict(self):
        """transaction_by_hash returns the transaction as a raw dict."""
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

        result = await client.transaction_by_hash("0xabc")
        assert isinstance(result, dict)
        assert result["hash"] == "0xabc"

    async def test_raises_not_found(self):
        """transaction_by_hash propagates NotFoundError for unknown hashes."""
        from aptos_sdk.errors import NotFoundError

        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "not found"}, 404)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        with pytest.raises(NotFoundError):
            await client.transaction_by_hash("0xdeadbeef")


# ---------------------------------------------------------------------------
# RestClient — legacy alias: transaction_by_version (lines 1743-1745)
# ---------------------------------------------------------------------------


class TestLegacyTransactionByVersion:
    async def test_returns_raw_dict(self):
        """transaction_by_version returns the transaction as a raw dict."""
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

        result = await client.transaction_by_version(42)
        assert isinstance(result, dict)
        assert result["version"] == "42"


# ---------------------------------------------------------------------------
# RestClient — legacy alias: transactions_by_account (lines 1759-1764)
# ---------------------------------------------------------------------------


class TestLegacyTransactionsByAccount:
    async def test_returns_list_of_dicts(self):
        """transactions_by_account returns account transactions as raw dicts."""
        client = RestClient("https://test/v1")
        raw = [
            {"hash": "0x1", "type": "user_transaction", "version": "1"},
            {"hash": "0x2", "type": "user_transaction", "version": "2"},
        ]
        mock_resp = _json_response(raw)
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.transactions_by_account(AccountAddress.ONE)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["hash"] == "0x1"

    async def test_forwards_limit_and_start(self):
        """transactions_by_account passes limit and start through to the API."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response([])
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        await client.transactions_by_account(AccountAddress.ONE, limit=5, start=10)
        call_kwargs = client._client.get.call_args
        params = call_kwargs.kwargs["params"]
        assert params["limit"] == 5
        assert params["start"] == 10


# ---------------------------------------------------------------------------
# RestClient — legacy alias: submit_and_wait_for_bcs_transaction (lines 1794-1796)
# ---------------------------------------------------------------------------


class TestLegacySubmitAndWaitForBcsTransaction:
    async def test_submits_waits_and_returns_raw_dict(self):
        """submit_and_wait_for_bcs_transaction submits, waits, then fetches the txn dict."""
        from aptos_sdk.chain_id import ChainId
        from aptos_sdk.transactions import RawTransaction, SignedTransaction

        account = _make_account()
        payload = _make_transfer_payload()
        raw_txn = RawTransaction(
            account.address, 0, payload, 100_000, 100, 9_999_999_999, ChainId(4)
        )
        auth = raw_txn.sign(account.private_key)
        signed_txn = SignedTransaction(raw_txn, auth)

        committed = {
            "hash": "0xwaitdone",
            "type": "user_transaction",
            "version": "10",
            "success": True,
        }
        client = RestClient("https://test/v1")

        # POST for submission, GET for wait_for_transaction and transaction_by_hash
        post_resp = _json_response({"hash": "0xwaitdone"})
        get_resp = _json_response(committed)

        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=post_resp)
        client._client.get = AsyncMock(return_value=get_resp)

        result = await client.submit_and_wait_for_bcs_transaction(signed_txn)
        assert isinstance(result, dict)
        assert result["hash"] == "0xwaitdone"
        assert result["success"] is True


# ---------------------------------------------------------------------------
# RestClient — legacy alias: view (lines 1812-1826)
# ---------------------------------------------------------------------------


class TestSubmitAndWait:
    async def test_submits_and_returns_committed_transaction(self):
        """submit_and_wait builds, signs, submits, and returns the committed Transaction."""
        account = _make_account()
        payload = _make_transfer_payload()

        client = RestClient("https://test/v1")
        client._chain_id = 4

        committed = {
            "hash": "0xcommitted",
            "type": "user_transaction",
            "version": "77",
            "success": True,
        }
        get_resp = _json_response(SAMPLE_ACCOUNT_INFO)
        committed_resp = _json_response(committed)
        post_resp = _json_response({"hash": "0xcommitted"})

        call_count = 0

        async def mock_get(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return get_resp  # sequence number lookup
            return committed_resp  # wait_for_transaction polling

        client._client = AsyncMock()
        client._client.get = mock_get
        client._client.post = AsyncMock(return_value=post_resp)

        txn = await client.submit_and_wait(account, payload)
        assert isinstance(txn, Transaction)
        assert txn.success is True
        assert txn.hash == "0xcommitted"


class TestLegacyView:
    async def test_returns_response_bytes(self):
        """view returns the raw response content as bytes."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response(["12345"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        result = await client.view(
            "0x1::coin::balance",
            ["0x1::aptos_coin::AptosCoin"],
            ["0x1"],
        )
        # Result should be bytes (the raw response content)
        assert isinstance(result, bytes)

    async def test_raises_on_error(self):
        """view propagates HTTP errors via _raise_for_status."""
        from aptos_sdk.errors import BadRequestError

        client = RestClient("https://test/v1")
        mock_resp = _json_response({"message": "bad request"}, 400)
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        with pytest.raises(BadRequestError):
            await client.view("0x1::foo::bar", [], [])

    async def test_with_ledger_version_param(self):
        """view passes ledger_version as a query parameter."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response(["0"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        await client.view(
            "0x1::coin::balance",
            ["0x1::aptos_coin::AptosCoin"],
            ["0x1"],
            ledger_version=99999,
        )
        call_kwargs = client._client.post.call_args
        params = call_kwargs.kwargs.get("params", {})
        assert params.get("ledger_version") == 99999

    async def test_sends_correct_json_body(self):
        """view sends the function, type_arguments and arguments in the JSON body."""
        client = RestClient("https://test/v1")
        mock_resp = _json_response(["result"])
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        await client.view(
            "0x1::coin::balance",
            ["0x1::aptos_coin::AptosCoin"],
            ["0x1"],
        )
        call_kwargs = client._client.post.call_args
        body = call_kwargs.kwargs.get("json", {})
        assert body["function"] == "0x1::coin::balance"
        assert body["type_arguments"] == ["0x1::aptos_coin::AptosCoin"]
        assert body["arguments"] == ["0x1"]
