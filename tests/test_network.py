# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for Network configuration module.
"""

import pytest
from aptos_sdk.network import Network, NetworkConfig


class TestNetworkEnum:
    """Tests for Network enum."""

    def test_mainnet_config(self):
        """Test mainnet configuration."""
        assert Network.MAINNET.name == "mainnet"
        assert Network.MAINNET.chain_id == 1
        assert "mainnet" in Network.MAINNET.fullnode_url
        assert Network.MAINNET.faucet_url is None  # No faucet on mainnet

    def test_testnet_config(self):
        """Test testnet configuration."""
        assert Network.TESTNET.name == "testnet"
        assert Network.TESTNET.chain_id == 2
        assert "testnet" in Network.TESTNET.fullnode_url
        assert Network.TESTNET.faucet_url is not None

    def test_devnet_config(self):
        """Test devnet configuration."""
        assert Network.DEVNET.name == "devnet"
        assert Network.DEVNET.chain_id == 4
        assert "devnet" in Network.DEVNET.fullnode_url
        assert Network.DEVNET.faucet_url is not None

    def test_local_config(self):
        """Test local network configuration."""
        assert Network.LOCAL.name == "local"
        assert "127.0.0.1" in Network.LOCAL.fullnode_url

    def test_from_string_lowercase(self):
        """Test from_string with lowercase names."""
        assert Network.from_string("mainnet") == Network.MAINNET
        assert Network.from_string("testnet") == Network.TESTNET
        assert Network.from_string("devnet") == Network.DEVNET
        assert Network.from_string("local") == Network.LOCAL

    def test_from_string_uppercase(self):
        """Test from_string with uppercase names."""
        assert Network.from_string("MAINNET") == Network.MAINNET
        assert Network.from_string("TESTNET") == Network.TESTNET

    def test_from_string_mixed_case(self):
        """Test from_string with mixed case names."""
        assert Network.from_string("MainNet") == Network.MAINNET
        assert Network.from_string("TestNet") == Network.TESTNET

    def test_from_string_invalid(self):
        """Test from_string with invalid network name."""
        with pytest.raises(ValueError, match="Unknown network"):
            Network.from_string("invalid_network")

    def test_str_representation(self):
        """Test string representation of networks."""
        assert str(Network.MAINNET) == "mainnet"
        assert str(Network.TESTNET) == "testnet"
        assert str(Network.DEVNET) == "devnet"


class TestNetworkConfig:
    """Tests for NetworkConfig dataclass."""

    def test_network_config_creation(self):
        """Test creating custom NetworkConfig."""
        config = NetworkConfig(
            name="custom",
            chain_id=99,
            fullnode_url="http://localhost:8080/v1",
            indexer_url="http://localhost:8090/v1/graphql",
            faucet_url="http://localhost:8081",
        )
        assert config.name == "custom"
        assert config.chain_id == 99
        assert config.fullnode_url == "http://localhost:8080/v1"
        assert config.indexer_url == "http://localhost:8090/v1/graphql"
        assert config.faucet_url == "http://localhost:8081"

    def test_network_config_immutable(self):
        """Test NetworkConfig is frozen/immutable."""
        with pytest.raises(Exception):  # FrozenInstanceError
            Network.MAINNET.value.name = "modified"

