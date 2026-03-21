"""Unit tests for config module."""

import pytest

from aptos_sdk_v2.config import AptosConfig, Network


class TestNetwork:
    def test_default_devnet(self):
        config = AptosConfig()
        assert config.network == Network.DEVNET
        assert "devnet" in config.node_url

    def test_mainnet(self):
        config = AptosConfig(network=Network.MAINNET)
        assert "mainnet" in config.node_url

    def test_custom_url(self):
        config = AptosConfig(fullnode_url="http://localhost:8080/v1")
        assert config.node_url == "http://localhost:8080/v1"

    def test_faucet_devnet(self):
        config = AptosConfig(network=Network.DEVNET)
        assert "devnet" in config.faucet_endpoint

    def test_faucet_mainnet_fails(self):
        config = AptosConfig(network=Network.MAINNET)
        with pytest.raises(ValueError):
            config.faucet_endpoint

    def test_custom_faucet(self):
        config = AptosConfig(faucet_url="http://localhost:8081")
        assert config.faucet_endpoint == "http://localhost:8081"

    def test_custom_network_no_url_raises(self):
        config = AptosConfig(network=Network.CUSTOM)
        with pytest.raises(ValueError):
            config.node_url

    def test_api_key(self):
        config = AptosConfig(api_key="test-key")
        assert config.api_key == "test-key"

    def test_defaults(self):
        config = AptosConfig()
        assert config.max_gas_amount == 200_000
        assert config.gas_unit_price == 100
        assert config.expiration_ttl == 600
        assert config.transaction_wait_secs == 20
        assert config.max_retries == 3
        assert config.api_key is None
