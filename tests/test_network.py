# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.network — NetworkConfig and Network constants.
"""

import dataclasses

import pytest

from aptos_sdk.network import Network, NetworkConfig

# ---------------------------------------------------------------------------
# NetworkConfig
# ---------------------------------------------------------------------------


class TestNetworkConfig:
    def test_is_frozen_dataclass(self):
        config = NetworkConfig(name="test", fullnode_url="http://localhost/v1")
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            config.name = "changed"  # type: ignore[misc]

    def test_optional_fields_default_to_none(self):
        config = NetworkConfig(name="minimal", fullnode_url="http://localhost/v1")
        assert config.faucet_url is None
        assert config.indexer_url is None
        assert config.chain_id is None

    def test_repr_contains_name_and_url(self):
        config = NetworkConfig(name="test", fullnode_url="http://localhost/v1")
        r = repr(config)
        assert "test" in r
        assert "http://localhost/v1" in r

    def test_repr_omits_none_optional_fields(self):
        config = NetworkConfig(name="test", fullnode_url="http://localhost/v1")
        r = repr(config)
        assert "faucet_url" not in r
        assert "indexer_url" not in r
        assert "chain_id" not in r

    def test_repr_includes_non_none_optional_fields(self):
        config = NetworkConfig(
            name="test",
            fullnode_url="http://localhost/v1",
            chain_id=42,
        )
        r = repr(config)
        assert "42" in r


# ---------------------------------------------------------------------------
# Network.MAINNET
# ---------------------------------------------------------------------------


class TestNetworkMainnet:
    def test_name(self):
        assert Network.MAINNET.name == "mainnet"

    def test_fullnode_url(self):
        assert "mainnet" in Network.MAINNET.fullnode_url
        assert Network.MAINNET.fullnode_url.startswith("https://")

    def test_no_faucet(self):
        assert Network.MAINNET.faucet_url is None

    def test_has_indexer(self):
        assert Network.MAINNET.indexer_url is not None
        assert "mainnet" in Network.MAINNET.indexer_url

    def test_chain_id(self):
        assert Network.MAINNET.chain_id == 1


# ---------------------------------------------------------------------------
# Network.TESTNET
# ---------------------------------------------------------------------------


class TestNetworkTestnet:
    def test_name(self):
        assert Network.TESTNET.name == "testnet"

    def test_fullnode_url(self):
        assert "testnet" in Network.TESTNET.fullnode_url

    def test_has_faucet(self):
        assert Network.TESTNET.faucet_url is not None
        assert "testnet" in Network.TESTNET.faucet_url

    def test_has_indexer(self):
        assert Network.TESTNET.indexer_url is not None

    def test_chain_id(self):
        assert Network.TESTNET.chain_id == 2


# ---------------------------------------------------------------------------
# Network.DEVNET
# ---------------------------------------------------------------------------


class TestNetworkDevnet:
    def test_name(self):
        assert Network.DEVNET.name == "devnet"

    def test_fullnode_url(self):
        assert "devnet" in Network.DEVNET.fullnode_url

    def test_has_faucet(self):
        assert Network.DEVNET.faucet_url is not None

    def test_chain_id_is_none(self):
        # Devnet chain ID resets with each deployment
        assert Network.DEVNET.chain_id is None


# ---------------------------------------------------------------------------
# Network.LOCALNET / Network.LOCAL
# ---------------------------------------------------------------------------


class TestNetworkLocalnet:
    def test_name(self):
        assert Network.LOCALNET.name == "localnet"

    def test_fullnode_url_localhost(self):
        assert "localhost" in Network.LOCALNET.fullnode_url

    def test_has_faucet(self):
        assert Network.LOCALNET.faucet_url is not None
        assert "localhost" in Network.LOCALNET.faucet_url

    def test_chain_id(self):
        assert Network.LOCALNET.chain_id == 4

    def test_local_alias_same_as_localnet(self):
        assert Network.LOCAL is Network.LOCALNET


# ---------------------------------------------------------------------------
# Network.custom
# ---------------------------------------------------------------------------


class TestNetworkCustom:
    def test_custom_minimal(self):
        config = Network.custom("https://my-node.example.com/v1")
        assert config.fullnode_url == "https://my-node.example.com/v1"
        assert config.name == "custom"
        assert config.faucet_url is None
        assert config.chain_id is None

    def test_custom_with_all_options(self):
        config = Network.custom(
            "https://my-node.example.com/v1",
            name="staging",
            faucet_url="https://faucet.example.com",
            indexer_url="https://indexer.example.com/graphql",
            chain_id=42,
        )
        assert config.name == "staging"
        assert config.faucet_url == "https://faucet.example.com"
        assert config.indexer_url == "https://indexer.example.com/graphql"
        assert config.chain_id == 42

    def test_custom_returns_networkconfig(self):
        config = Network.custom("https://node.example.com/v1")
        assert isinstance(config, NetworkConfig)

    def test_custom_is_frozen(self):
        config = Network.custom("https://node.example.com/v1")
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            config.name = "changed"  # type: ignore[misc]
