# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""Network configuration for the Aptos Python SDK.

This module provides :class:`NetworkConfig`, an immutable dataclass holding
all connection parameters for a single Aptos network endpoint, and
:class:`Network`, a namespace of pre-configured constants for the well-known
Aptos networks (mainnet, testnet, devnet, localnet).

Typical usage::

    from aptos_sdk.network import Network

    # Use a pre-configured network
    config = Network.TESTNET
    print(config.fullnode_url)    # https://fullnode.testnet.aptoslabs.com/v1
    print(config.faucet_url)      # https://faucet.testnet.aptoslabs.com
    print(config.chain_id)        # 2

    # Build a custom configuration
    config = Network.custom(
        "https://my-node.example.com/v1",
        name="staging",
        faucet_url="https://my-faucet.example.com",
        chain_id=42,
    )
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkConfig:
    """Immutable configuration for connecting to an Aptos network.

    All fields except *fullnode_url* and *name* are optional because not
    every deployment exposes a faucet or indexer, and the chain ID may not
    always be known in advance.

    Attributes:
        name: Human-readable label for this network (e.g. ``"mainnet"``).
        fullnode_url: Base URL of the Aptos Fullnode REST API, including
            the ``/v1`` path prefix.
        faucet_url: Base URL of the Aptos Faucet service.  ``None`` for
            networks that do not expose a public faucet (e.g. mainnet).
        indexer_url: Base URL of the Aptos Indexer GraphQL endpoint.
            ``None`` when the indexer is not available.
        chain_id: Numeric chain identifier for this network.  ``None``
            when the value is not statically known (it can be fetched from
            the fullnode at runtime via ``GET /v1``).
    """

    name: str
    fullnode_url: str
    faucet_url: str | None = None
    indexer_url: str | None = None
    chain_id: int | None = None

    def __repr__(self) -> str:
        parts = [f"name={self.name!r}", f"fullnode_url={self.fullnode_url!r}"]
        if self.faucet_url is not None:
            parts.append(f"faucet_url={self.faucet_url!r}")
        if self.indexer_url is not None:
            parts.append(f"indexer_url={self.indexer_url!r}")
        if self.chain_id is not None:
            parts.append(f"chain_id={self.chain_id!r}")
        return f"NetworkConfig({', '.join(parts)})"


class Network:
    """Pre-configured network constants for well-known Aptos deployments.

    This class acts as a namespace; it is not meant to be instantiated.
    Each class attribute is a :class:`NetworkConfig` instance that can be
    passed directly to ``RestClient`` or ``FaucetClient``.

    Example::

        from aptos_sdk.network import Network
        from aptos_sdk.async_client import RestClient

        async with RestClient(Network.MAINNET.fullnode_url) as client:
            info = await client.get_ledger_info()

    Class attributes:
        MAINNET:  Production network.  No public faucet.  Chain ID 1.
        TESTNET:  Stable test network with a public faucet.  Chain ID 2.
        DEVNET:   Frequently-reset developer network with a public faucet.
                  Chain ID is not static (resets with each deployment).
        LOCALNET: Local development node running on ``localhost``.
                  Chain ID 4 (Aptos CLI default).
        LOCAL:    Alias for :attr:`LOCALNET` — kept for backward
                  compatibility with the existing SDK.
    """

    MAINNET: NetworkConfig = NetworkConfig(
        name="mainnet",
        fullnode_url="https://fullnode.mainnet.aptoslabs.com/v1",
        indexer_url="https://indexer.mainnet.aptoslabs.com/v1/graphql",
        chain_id=1,
    )

    TESTNET: NetworkConfig = NetworkConfig(
        name="testnet",
        fullnode_url="https://fullnode.testnet.aptoslabs.com/v1",
        faucet_url="https://faucet.testnet.aptoslabs.com",
        indexer_url="https://indexer.testnet.aptoslabs.com/v1/graphql",
        chain_id=2,
    )

    DEVNET: NetworkConfig = NetworkConfig(
        name="devnet",
        fullnode_url="https://fullnode.devnet.aptoslabs.com/v1",
        faucet_url="https://faucet.devnet.aptoslabs.com",
        indexer_url="https://indexer.devnet.aptoslabs.com/v1/graphql",
    )

    LOCALNET: NetworkConfig = NetworkConfig(
        name="localnet",
        fullnode_url="http://localhost:8080/v1",
        faucet_url="http://localhost:8081",
        chain_id=4,
    )

    # Backward-compatibility alias — the existing SDK exposes ``Network.LOCAL``.
    LOCAL: NetworkConfig = LOCALNET

    @staticmethod
    def custom(
        fullnode_url: str,
        *,
        name: str = "custom",
        faucet_url: str | None = None,
        indexer_url: str | None = None,
        chain_id: int | None = None,
    ) -> NetworkConfig:
        """Create a :class:`NetworkConfig` for an arbitrary Aptos deployment.

        This factory is useful for connecting to private networks, local
        test clusters, or any other endpoint not covered by the built-in
        constants.

        Args:
            fullnode_url: Base URL of the Aptos Fullnode REST API
                (required).  Should include the ``/v1`` path prefix,
                e.g. ``"https://my-node.example.com/v1"``.
            name: Optional human-readable label for this network.
                Defaults to ``"custom"``.
            faucet_url: Optional faucet base URL.
            indexer_url: Optional Indexer GraphQL endpoint URL.
            chain_id: Optional chain identifier.

        Returns:
            A new, frozen :class:`NetworkConfig` instance.

        Example::

            cfg = Network.custom(
                "https://my-private-node.internal/v1",
                name="staging",
                chain_id=7,
            )
        """
        return NetworkConfig(
            name=name,
            fullnode_url=fullnode_url,
            faucet_url=faucet_url,
            indexer_url=indexer_url,
            chain_id=chain_id,
        )
