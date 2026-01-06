# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Pytest configuration and shared fixtures for the Aptos SDK test suite.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# =============================================================================
# Network Fixtures
# =============================================================================


@pytest.fixture
def testnet_url():
    """Testnet fullnode URL."""
    return "https://fullnode.testnet.aptoslabs.com/v1"


@pytest.fixture
def devnet_url():
    """Devnet fullnode URL."""
    return "https://fullnode.devnet.aptoslabs.com/v1"


@pytest.fixture
def local_url():
    """Local node URL."""
    return "http://127.0.0.1:8080/v1"


# =============================================================================
# Account Fixtures
# =============================================================================


@pytest.fixture
def test_private_key_ed25519():
    """A deterministic Ed25519 private key for testing."""
    return "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"


@pytest.fixture
def test_private_key_secp256k1():
    """A deterministic Secp256k1 private key for testing."""
    return "0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"


# =============================================================================
# Mock Client Fixtures
# =============================================================================


@pytest.fixture
def mock_httpx_client():
    """Mock httpx.AsyncClient for testing without network calls."""
    with patch("httpx.AsyncClient") as mock:
        client = MagicMock()
        client.get = AsyncMock()
        client.post = AsyncMock()
        client.aclose = AsyncMock()
        mock.return_value = client
        yield client


@pytest.fixture
def mock_rest_client_response():
    """Factory for creating mock HTTP responses."""

    def _create_response(status_code: int, json_data: dict = None, text: str = ""):
        response = MagicMock()
        response.status_code = status_code
        response.json.return_value = json_data or {}
        response.text = text
        return response

    return _create_response


# =============================================================================
# BCS Fixtures
# =============================================================================


@pytest.fixture
def serializer():
    """Fresh Serializer instance."""
    from aptos_sdk.bcs import Serializer

    return Serializer()


@pytest.fixture
def deserializer_factory():
    """Factory for creating Deserializer from bytes."""
    from aptos_sdk.bcs import Deserializer

    def _create(data: bytes):
        return Deserializer(data)

    return _create


# =============================================================================
# Address Fixtures
# =============================================================================


@pytest.fixture
def address_one():
    """Standard address 0x1."""
    from aptos_sdk.account_address import AccountAddress

    return AccountAddress.from_str("0x1")


@pytest.fixture
def address_zero():
    """Standard address 0x0."""
    from aptos_sdk.account_address import AccountAddress

    return AccountAddress.from_str("0x0")


# =============================================================================
# Pytest Configuration
# =============================================================================


def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")

