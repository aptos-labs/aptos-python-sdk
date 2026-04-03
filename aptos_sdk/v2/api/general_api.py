"""General API — ledger info, blocks, view functions, table items."""

from __future__ import annotations

from typing import Any

from ..config import AptosConfig
from .http_client import HttpClient


class GeneralApi:
    """General blockchain queries: ledger info, blocks, view functions."""

    __slots__ = ("_config", "_client")

    def __init__(self, config: AptosConfig, client: HttpClient) -> None:
        self._config = config
        self._client = client

    async def get_ledger_info(self) -> dict[str, Any]:
        return await self._client.get(self._config.node_url)

    async def get_chain_id(self) -> int:
        info = await self.get_ledger_info()
        return int(info["chain_id"])

    async def get_block_by_height(
        self, height: int, *, with_transactions: bool = False
    ) -> dict[str, Any]:
        url = f"{self._config.node_url}/blocks/by_height/{height}"
        if with_transactions:
            url += "?with_transactions=true"
        return await self._client.get(url)

    async def get_block_by_version(
        self, version: int, *, with_transactions: bool = False
    ) -> dict[str, Any]:
        url = f"{self._config.node_url}/blocks/by_version/{version}"
        if with_transactions:
            url += "?with_transactions=true"
        return await self._client.get(url)

    async def get_table_item(
        self,
        table_handle: str,
        key_type: str,
        value_type: str,
        key: Any,
    ) -> dict[str, Any]:
        url = f"{self._config.node_url}/tables/{table_handle}/item"
        return await self._client.post(
            url,
            json={
                "key_type": key_type,
                "value_type": value_type,
                "key": key,
            },
        )

    async def view(
        self,
        module: str,
        function: str,
        ty_args: list[str],
        args: list[str],
    ) -> list[Any]:
        """Execute a view function (read-only) using JSON arguments."""
        url = f"{self._config.node_url}/view"
        return await self._client.post_view(
            url,
            json={
                "function": f"{module}::{function}",
                "type_arguments": ty_args,
                "arguments": args,
            },
        )

    async def view_bcs(
        self,
        module: str,
        function: str,
        ty_args: list[str],
        args: bytes,
    ) -> bytes:
        """Execute a view function with BCS-encoded arguments and return BCS bytes.

        This is useful for complex argument types (vectors, options) that are
        difficult to represent as JSON strings.
        """
        from ..bcs import Serializer
        from ..transactions.payload import EntryFunction, ModuleId
        from ..types.account_address import AccountAddress
        from ..types.type_tag import TypeTag

        # Build the BCS payload for the view request
        module_id = ModuleId.from_str(module)
        parsed_ty_args = [TypeTag.from_str(t) for t in ty_args] if ty_args else []

        ser = Serializer()
        module_id.serialize(ser)
        ser.str(function)
        ser.uleb128(len(parsed_ty_args))
        for ty in parsed_ty_args:
            ty.serialize(ser)
        ser.to_bytes(args)
        bcs_body = ser.output()

        url = f"{self._config.node_url}/view"
        session = self._client._ensure_session()
        async with session.request(
            "POST",
            url,
            data=bcs_body,
            headers={
                "Content-Type": "application/x.aptos.view_function+bcs",
                "Accept": "application/x-bcs",
            },
        ) as resp:
            if resp.status >= 400:
                from ..errors import ApiError

                body = await resp.text()
                raise ApiError(body, resp.status)
            return await resp.read()
