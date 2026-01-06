# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Fungible Asset (FA) utilities and helpers.

Provides functions for working with the Fungible Asset standard (FA),
which is the modern standard for fungible tokens on Aptos.

Example:
    >>> from aptos_sdk import RestClient, fungible_asset as fa
    >>>
    >>> async with RestClient(Network.MAINNET.fullnode_url) as client:
    ...     balance = await fa.get_balance(client, address, fa_address)
    ...     metadata = await fa.get_metadata(client, fa_address)
    ...     print(f"Balance: {balance} {metadata.symbol}")
"""

from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .async_client import RestClient
    from .account_address import AccountAddress


@dataclass
class FungibleAssetMetadata:
    """
    Metadata for a Fungible Asset.

    Attributes:
        name: Human-readable name of the asset.
        symbol: Trading symbol (e.g., "APT", "USDC").
        decimals: Number of decimal places.
        icon_uri: Optional URI for the asset icon.
        project_uri: Optional URI for the project website.
    """

    name: str
    symbol: str
    decimals: int
    icon_uri: Optional[str] = None
    project_uri: Optional[str] = None


# Common FA addresses
APT_FA_ADDRESS = "0xa"  # Native APT as FA


async def get_metadata(
    client: "RestClient",
    fa_address: "AccountAddress",
) -> Optional[FungibleAssetMetadata]:
    """
    Get metadata for a Fungible Asset.

    Args:
        client: The RestClient to use for the query.
        fa_address: The address of the Fungible Asset metadata object.

    Returns:
        FungibleAssetMetadata if found, None otherwise.

    Example:
        >>> metadata = await fa.get_metadata(client, usdc_address)
        >>> print(f"Name: {metadata.name}, Symbol: {metadata.symbol}")
    """
    try:
        resource = await client.account_resource(
            fa_address,
            "0x1::fungible_asset::Metadata",
        )

        if resource and "data" in resource:
            data = resource["data"]
            return FungibleAssetMetadata(
                name=data.get("name", ""),
                symbol=data.get("symbol", ""),
                decimals=int(data.get("decimals", 0)),
                icon_uri=data.get("icon_uri"),
                project_uri=data.get("project_uri"),
            )
        return None

    except Exception:
        return None


async def get_balance(
    client: "RestClient",
    owner: "AccountAddress",
    fa_address: "AccountAddress",
) -> int:
    """
    Get the balance of a Fungible Asset for an account.

    Args:
        client: The RestClient to use for the query.
        owner: The account address to check balance for.
        fa_address: The address of the Fungible Asset metadata object.

    Returns:
        The balance as an integer (in smallest units).

    Example:
        >>> balance = await fa.get_balance(client, alice_address, usdc_address)
        >>> print(f"Balance: {balance}")
    """
    from .transactions import TransactionArgument
    from .bcs import Serializer
    from .type_tag import TypeTag, StructTag

    try:
        result = await client.view_bcs_payload(
            "0x1::primary_fungible_store",
            "balance",
            [TypeTag(StructTag.from_str("0x1::fungible_asset::Metadata"))],
            [
                TransactionArgument(owner, Serializer.struct),
                TransactionArgument(fa_address, Serializer.struct),
            ],
        )

        if result and len(result) > 0:
            return int(result[0])
        return 0

    except Exception:
        return 0


async def get_supply(
    client: "RestClient",
    fa_address: "AccountAddress",
) -> Optional[int]:
    """
    Get the total supply of a Fungible Asset.

    Args:
        client: The RestClient to use for the query.
        fa_address: The address of the Fungible Asset metadata object.

    Returns:
        The total supply as an integer, or None if not available.

    Example:
        >>> supply = await fa.get_supply(client, token_address)
        >>> if supply:
        ...     print(f"Total supply: {supply}")
    """
    try:
        resource = await client.account_resource(
            fa_address,
            "0x1::fungible_asset::Supply",
        )

        if resource and "data" in resource:
            data = resource["data"]
            current = data.get("current")
            if current is not None:
                return int(current)
        return None

    except Exception:
        return None


async def is_frozen(
    client: "RestClient",
    owner: "AccountAddress",
    fa_address: "AccountAddress",
) -> bool:
    """
    Check if an account's Fungible Asset store is frozen.

    Args:
        client: The RestClient to use for the query.
        owner: The account address to check.
        fa_address: The address of the Fungible Asset metadata object.

    Returns:
        True if the account is frozen, False otherwise.

    Example:
        >>> if await fa.is_frozen(client, alice_address, token_address):
        ...     print("Account is frozen")
    """
    from .transactions import TransactionArgument
    from .bcs import Serializer
    from .type_tag import TypeTag, StructTag

    try:
        result = await client.view_bcs_payload(
            "0x1::primary_fungible_store",
            "is_frozen",
            [TypeTag(StructTag.from_str("0x1::fungible_asset::Metadata"))],
            [
                TransactionArgument(owner, Serializer.struct),
                TransactionArgument(fa_address, Serializer.struct),
            ],
        )

        if result and len(result) > 0:
            return bool(result[0])
        return False

    except Exception:
        return False


def format_amount(amount: int, decimals: int) -> str:
    """
    Format a raw amount with decimal places.

    Args:
        amount: The raw amount in smallest units.
        decimals: Number of decimal places.

    Returns:
        Formatted string representation.

    Example:
        >>> fa.format_amount(1000000, 6)
        '1.0'
        >>> fa.format_amount(1500000, 6)
        '1.5'
    """
    if decimals == 0:
        return str(amount)

    divisor = 10**decimals
    whole = amount // divisor
    fraction = amount % divisor

    if fraction == 0:
        return str(whole)

    fraction_str = str(fraction).zfill(decimals).rstrip("0")
    return f"{whole}.{fraction_str}"


def parse_amount(amount_str: str, decimals: int) -> int:
    """
    Parse a formatted amount string to raw units.

    Args:
        amount_str: The formatted amount (e.g., "1.5").
        decimals: Number of decimal places.

    Returns:
        The amount in smallest units.

    Example:
        >>> fa.parse_amount("1.5", 6)
        1500000
        >>> fa.parse_amount("100", 8)
        10000000000
    """
    if "." not in amount_str:
        return int(amount_str) * (10**decimals)

    parts = amount_str.split(".")
    whole = int(parts[0])
    fraction_str = parts[1]

    # Pad or truncate fraction to match decimals
    if len(fraction_str) > decimals:
        fraction_str = fraction_str[:decimals]
    else:
        fraction_str = fraction_str.ljust(decimals, "0")

    fraction = int(fraction_str)
    return whole * (10**decimals) + fraction

