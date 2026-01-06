# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Aptos Names Service (ANS) utilities.

Provides functions for resolving human-readable names to addresses
and looking up names for addresses.

Example:
    >>> from aptos_sdk import RestClient, ans
    >>>
    >>> async with RestClient(Network.MAINNET.fullnode_url) as client:
    ...     address = await ans.get_address(client, "alice.apt")
    ...     print(f"alice.apt -> {address}")
"""

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .async_client import RestClient
    from .account_address import AccountAddress


# ANS contract addresses
ANS_CONTRACT_ADDRESS = "0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c"

# Router contract for name resolution
ROUTER_ADDRESS = "0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c"


async def get_address(
    client: "RestClient",
    name: str,
) -> Optional["AccountAddress"]:
    """
    Resolve an ANS name to an account address.

    Args:
        client: The RestClient to use for the lookup.
        name: The ANS name to resolve (e.g., "alice.apt" or "alice").

    Returns:
        The resolved AccountAddress, or None if the name is not registered.

    Example:
        >>> address = await ans.get_address(client, "alice.apt")
        >>> if address:
        ...     print(f"Found: {address}")
        ... else:
        ...     print("Name not registered")
    """
    from .account_address import AccountAddress
    from .transactions import TransactionArgument
    from .bcs import Serializer
    from .type_tag import TypeTag, StructTag

    # Normalize name (remove .apt suffix if present)
    if name.endswith(".apt"):
        name = name[:-4]

    # Split into subdomain and domain if applicable
    parts = name.split(".")
    if len(parts) == 1:
        # Simple name like "alice"
        subdomain = ""
        domain = parts[0]
    elif len(parts) == 2:
        # Subdomain like "sub.alice"
        subdomain = parts[0]
        domain = parts[1]
    else:
        # Invalid format
        return None

    try:
        # Call the view function to resolve the name
        result = await client.view_bcs_payload(
            f"{ANS_CONTRACT_ADDRESS}::router",
            "get_target_addr",
            [],
            [
                TransactionArgument(domain, Serializer.str),
                TransactionArgument(subdomain, Serializer.str),
            ],
        )

        # Parse result - it returns Option<address>
        if result and len(result) > 0:
            # Result is a vector with the option
            option_value = result[0]
            if option_value and "vec" in option_value:
                vec = option_value["vec"]
                if vec and len(vec) > 0:
                    return AccountAddress.from_str(vec[0])
        return None

    except Exception:
        # Name not found or error in resolution
        return None


async def get_primary_name(
    client: "RestClient",
    address: "AccountAddress",
) -> Optional[str]:
    """
    Get the primary ANS name for an address.

    Args:
        client: The RestClient to use for the lookup.
        address: The account address to look up.

    Returns:
        The primary name (e.g., "alice.apt"), or None if no primary name is set.

    Example:
        >>> name = await ans.get_primary_name(client, address)
        >>> if name:
        ...     print(f"Primary name: {name}")
    """
    from .transactions import TransactionArgument
    from .bcs import Serializer

    try:
        result = await client.view_bcs_payload(
            f"{ANS_CONTRACT_ADDRESS}::router",
            "get_primary_name",
            [],
            [
                TransactionArgument(address, Serializer.struct),
            ],
        )

        if result and len(result) >= 2:
            domain = result[0]
            subdomain = result[1]

            if domain:
                if subdomain:
                    return f"{subdomain}.{domain}.apt"
                return f"{domain}.apt"
        return None

    except Exception:
        return None


def is_valid_ans_name(name: str) -> bool:
    """
    Check if a string is a valid ANS name format.

    Valid names:
    - 3-63 characters
    - Lowercase letters, numbers, and hyphens
    - Cannot start or end with hyphen
    - Optional .apt suffix

    Args:
        name: The name to validate.

    Returns:
        True if the name format is valid, False otherwise.

    Example:
        >>> ans.is_valid_ans_name("alice.apt")
        True
        >>> ans.is_valid_ans_name("a")  # Too short
        False
    """
    import re

    # Remove .apt suffix if present
    if name.endswith(".apt"):
        name = name[:-4]

    # Check length
    if len(name) < 3 or len(name) > 63:
        return False

    # Check format: lowercase alphanumeric and hyphens, no leading/trailing hyphens
    pattern = r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$"
    return bool(re.match(pattern, name))

