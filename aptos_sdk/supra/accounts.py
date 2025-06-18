from enum import Enum
from typing import Optional

from aptos_sdk.account_address import AccountAddress

from .exceptitions import (
    SupraAcceptTypeNotSupported,
    SupraApiError,
    SupraCursorDecodeError,
)
from .types import (
    DEFAULT_SIZE_OF_PAGE,
    MAX_NUM_OF_TRANSACTIONS_TO_RETURN,
    AccountAutomatedTxPagination,
    AccountTxPaginationWithOrder,
    SupraAccountData,
)


class SupraRestAcceptType(str, Enum):
    JSON = "application/json"
    OCTET = "application/octet-stream"
    BCS = "application/x-bcs"


class BaseSupraAPI:
    """Base class with common functionality for all Supra API modules"""

    def __init__(self, http_client, base_url: str):
        self._client = http_client
        self._base_url = base_url

    def _check_accept_type(self, accept_type: str, unsupported: List[str]) -> None:
        """Check if accept type is supported (mirrors reject_unsupported_header)"""
        if accept_type in unsupported:
            supported = [
                t
                for t in [e.value for e in SupraRestAcceptType]
                if t not in unsupported
            ]
            raise SupraAcceptTypeNotSupported(accept_type, supported)

    def _handle_response(self, response, accept_type: str, data_class=None):
        """Generic response handler"""
        if response.status_code >= 400:
            raise SupraApiError(f"API Error: {response.text}", response.status_code)

        # if accept_type == SupraRestAcceptType.JSON.value:
        #     data = response.json()
        #     if data_class:
        #         if isinstance(data, list):
        #             return [data_class.from_dict(item) for item in data]
        #         else:
        #             return data_class.from_dict(data)
        #     return data
        # else:
        #     return response.content
        return response.content

    def _get_cursor_from_response(self, response) -> str:
        """Extract cursor from response headers"""
        return response.headers.get("x-supra-cursor", "")


class AccountAPI(BaseSupraAPI):
    """Supra v3 Accounts API endpoints."""

    async def get_account_v3(
        self,
        address: AccountAddress,
        accept_type: str = SupraRestAcceptType.JSON.value,
    ):
        """GET /rpc/v3/accounts/{address}"""
        url = f"{self.base_url}/rpc/v3/accounts/{address}"
        headers = {"Accept": accept_type}

        resp = await self._client.get(url, headers=headers)

        return self._handle_response(resp, accept_type, SupraAccountData)

    async def get_account_transactions_v3(
        self,
        address: AccountAddress,
        pagination_with_order: Optional[AccountTxPaginationWithOrder] = None,
        accept_type: str = SupraRestAcceptType.JSON.value,
    ):
        # ) -> List[SupraTransaction]:
        """GET /rpc/v3/accounts/{address}/transactions"""
        self._check_accept_type(
            accept_type,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )

        url = f"{self.base_url}/rpc/v3/accounts/{address}/transactions"
        headers = {"Accept": accept_type}
        params = pagination_with_order.to_params() if pagination_with_order else {}

        resp = await self._client.get(url, headers=headers, params=params)
        # return self._handle_response(resp, accept_type, SupraTransaction)
        return resp.content

    async def get_account_automated_transactions_v3(
        self,
        address: AccountAddress,
        pagination: Optional[AccountAutomatedTxPagination] = None,
        accept_type: str = SupraRestAcceptType.JSON.value,
    ):
        """GET /rpc/v3/accounts/{address}/automated_transactions"""
        self._check_accept_type(
            accept_type,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )

        start_block_height = pagination.count if pagination else None
        count = (
            min(pagination.count, MAX_NUM_OF_TRANSACTIONS_TO_RETURN)
            if pagination and pagination.count is not None
            else DEFAULT_SIZE_OF_PAGE
        )

        cursor_bytes = None
        if pagination and pagination.count is not None:
            try:
                cursor_bytes = bytes.fromhex(pagination.cursor)
            except:
                raise SupraCursorDecodeError(pagination.cursor)

        ascending = pagination.ascending if pagination else False

        url = f"{self._base_url}/rpc/v3/accounts/{address}/automated_transactions"
        headers = {"Accept": accept_type}
        params = pagination.to_params() if pagination else {}

        resp = await self._client.get(url, headers=headers, params=params)

        data = resp.json()
        # TODO: need to extract Txn data form `data`
        resp_cursor = resp.headers.get("x-supra-cursor", "")

        return data, resp_cursor

    async def coin_transactions_v3(self):
        """GET /rpc/v3/accounts/{address}/coin_transactions"""
        pass

    async def get_account_resources_v3(self):
        """GET /rpc/v3/accounts/{address}/resources"""
        pass

    async def get_account_modules_v3(self):
        """GET /rpc/v3/accounts/{address}/modules"""
        pass

    async def get_account_specific_resource_v3(self):
        """GET /rpc/v3/accounts/{address}/resources/{resource_type}"""
        pass

    async def get_account_specific_modules_v3(self):
        """GET /rpc/v3/accounts/{address}/modules/{module_name}"""
        pass
