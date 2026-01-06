# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Network configuration and presets for Aptos networks.

Provides easy access to well-known network endpoints:

    from aptos_sdk import Network, RestClient

    # Using enum
    async with RestClient(Network.TESTNET.fullnode_url) as client:
        ...

    # Using string (also works)
    async with RestClient(Network.from_string("testnet").fullnode_url) as client:
        ...
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


@dataclass(frozen=True)
class NetworkConfig:
    """
    Configuration for an Aptos network.

    Attributes:
        name: Human-readable network name.
        chain_id: The chain ID for this network.
        fullnode_url: URL of the fullnode REST API.
        indexer_url: URL of the indexer GraphQL API (if available).
        faucet_url: URL of the faucet service (if available).
    """

    name: str
    chain_id: int
    fullnode_url: str
    indexer_url: Optional[str] = None
    faucet_url: Optional[str] = None


class Network(Enum):
    """
    Well-known Aptos networks with pre-configured endpoints.

    Example:
        >>> from aptos_sdk import Network, RestClient
        >>>
        >>> # Use testnet
        >>> async with RestClient(Network.TESTNET.fullnode_url) as client:
        ...     info = await client.info()
        ...     print(f"Chain ID: {info['chain_id']}")
        >>>
        >>> # Get faucet URL
        >>> print(Network.DEVNET.faucet_url)
        'https://faucet.devnet.aptoslabs.com'
    """

    MAINNET = NetworkConfig(
        name="mainnet",
        chain_id=1,
        fullnode_url="https://fullnode.mainnet.aptoslabs.com/v1",
        indexer_url="https://indexer.mainnet.aptoslabs.com/v1/graphql",
        faucet_url=None,  # No faucet on mainnet
    )

    TESTNET = NetworkConfig(
        name="testnet",
        chain_id=2,
        fullnode_url="https://fullnode.testnet.aptoslabs.com/v1",
        indexer_url="https://indexer.testnet.aptoslabs.com/v1/graphql",
        faucet_url="https://faucet.testnet.aptoslabs.com",
    )

    DEVNET = NetworkConfig(
        name="devnet",
        chain_id=4,
        fullnode_url="https://fullnode.devnet.aptoslabs.com/v1",
        indexer_url="https://indexer.devnet.aptoslabs.com/v1/graphql",
        faucet_url="https://faucet.devnet.aptoslabs.com",
    )

    LOCAL = NetworkConfig(
        name="local",
        chain_id=4,  # Local networks typically use chain ID 4
        fullnode_url="http://127.0.0.1:8080/v1",
        indexer_url=None,
        faucet_url="http://127.0.0.1:8081",
    )

    @property
    def name(self) -> str:
        """Get the network name."""
        return self.value.name

    @property
    def chain_id(self) -> int:
        """Get the chain ID."""
        return self.value.chain_id

    @property
    def fullnode_url(self) -> str:
        """Get the fullnode REST API URL."""
        return self.value.fullnode_url

    @property
    def indexer_url(self) -> Optional[str]:
        """Get the indexer GraphQL URL, if available."""
        return self.value.indexer_url

    @property
    def faucet_url(self) -> Optional[str]:
        """Get the faucet URL, if available."""
        return self.value.faucet_url

    @classmethod
    def from_string(cls, network: str) -> "Network":
        """
        Get a Network enum from a string name.

        Args:
            network: Network name (case-insensitive): "mainnet", "testnet", "devnet", "local"

        Returns:
            The corresponding Network enum value.

        Raises:
            ValueError: If the network name is not recognized.

        Example:
            >>> Network.from_string("testnet")
            <Network.TESTNET: NetworkConfig(...)>
            >>> Network.from_string("MAINNET")
            <Network.MAINNET: NetworkConfig(...)>
        """
        name_upper = network.upper()
        try:
            return cls[name_upper]
        except KeyError:
            valid = ", ".join(n.name.lower() for n in cls)
            raise ValueError(
                f"Unknown network '{network}'. Valid networks: {valid}"
            ) from None

    def __str__(self) -> str:
        """Return the lowercase network name."""
        return self.value.name


# String constants for backward compatibility and convenience
MAINNET_URL = Network.MAINNET.fullnode_url
TESTNET_URL = Network.TESTNET.fullnode_url
DEVNET_URL = Network.DEVNET.fullnode_url

