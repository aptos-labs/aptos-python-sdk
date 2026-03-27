"""Configuration for the Aptos SDK — network selection and client settings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Network(Enum):
    MAINNET = "mainnet"
    TESTNET = "testnet"
    DEVNET = "devnet"
    LOCAL = "local"
    CUSTOM = "custom"


NETWORK_URLS: dict[Network, str] = {
    Network.MAINNET: "https://fullnode.mainnet.aptoslabs.com/v1",
    Network.TESTNET: "https://fullnode.testnet.aptoslabs.com/v1",
    Network.DEVNET: "https://fullnode.devnet.aptoslabs.com/v1",
    Network.LOCAL: "http://127.0.0.1:8080/v1",
}

FAUCET_URLS: dict[Network, str] = {
    Network.TESTNET: "https://faucet.testnet.aptoslabs.com",
    Network.DEVNET: "https://faucet.devnet.aptoslabs.com",
    Network.LOCAL: "http://127.0.0.1:8081",
}


@dataclass(frozen=True, slots=True)
class AptosConfig:
    """Configuration for the Aptos client."""

    network: Network = Network.DEVNET
    fullnode_url: str | None = None
    faucet_url: str | None = None
    max_gas_amount: int = 200_000
    gas_unit_price: int = 100
    expiration_ttl: int = 600
    transaction_wait_secs: int = 20
    max_retries: int = 3
    api_key: str | None = None

    @property
    def node_url(self) -> str:
        if self.fullnode_url:
            return self.fullnode_url
        if self.network in NETWORK_URLS:
            return NETWORK_URLS[self.network]
        raise ValueError(f"No fullnode URL configured for network {self.network}")

    @property
    def faucet_endpoint(self) -> str:
        if self.faucet_url:
            return self.faucet_url
        if self.network in FAUCET_URLS:
            return FAUCET_URLS[self.network]
        raise ValueError(f"No faucet URL available for network {self.network}")
