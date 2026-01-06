# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for AccountAddress module.
"""

import pytest
from dataclasses import dataclass
from aptos_sdk.account_address import AccountAddress
from aptos_sdk import ed25519


@dataclass
class AddressTestCase:
    """Test case for address formatting."""

    longWith0x: str
    longWithout0x: str
    shortWith0x: str
    shortWithout0x: str


# Test addresses for various scenarios
ADDRESS_ZERO = AddressTestCase(
    longWith0x="0x0000000000000000000000000000000000000000000000000000000000000000",
    longWithout0x="0000000000000000000000000000000000000000000000000000000000000000",
    shortWith0x="0x0",
    shortWithout0x="0",
)

ADDRESS_F = AddressTestCase(
    longWith0x="0x000000000000000000000000000000000000000000000000000000000000000f",
    longWithout0x="000000000000000000000000000000000000000000000000000000000000000f",
    shortWith0x="0xf",
    shortWithout0x="f",
)

ADDRESS_F_PADDED_SHORT_FORM = AddressTestCase(
    longWith0x="0x000000000000000000000000000000000000000000000000000000000000000f",
    longWithout0x="000000000000000000000000000000000000000000000000000000000000000f",
    shortWith0x="0x0f",
    shortWithout0x="0f",
)

ADDRESS_TEN = AddressTestCase(
    longWith0x="0x0000000000000000000000000000000000000000000000000000000000000010",
    longWithout0x="0000000000000000000000000000000000000000000000000000000000000010",
    shortWith0x="0x10",
    shortWithout0x="10",
)

ADDRESS_OTHER = AddressTestCase(
    longWith0x="0xca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    longWithout0x="ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    shortWith0x="0xca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    shortWithout0x="ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
)


class TestAddressDerivation:
    """Tests for address derivation functions."""

    def test_multi_ed25519(self):
        """Test address derivation from multi-ed25519 key."""
        private_key_1 = ed25519.PrivateKey.from_str(
            "4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        private_key_2 = ed25519.PrivateKey.from_str(
            "1e70e49b78f976644e2c51754a2f049d3ff041869c669523ba95b172c7329901"
        )
        multisig_public_key = ed25519.MultiPublicKey(
            [private_key_1.public_key(), private_key_2.public_key()], 1
        )

        expected = AccountAddress.from_str_relaxed(
            "835bb8c5ee481062946b18bbb3b42a40b998d6bf5316ca63834c959dc739acf0"
        )
        actual = AccountAddress.from_key(multisig_public_key)
        assert actual == expected

    def test_resource_account(self):
        """Test resource account address derivation."""
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "ee89f8c763c27f9d942d496c1a0dcf32d5eacfe78416f9486b8db66155b163b0"
        )
        actual = AccountAddress.for_resource_account(base_address, b"\x0b\x00\x0b")
        assert actual == expected

    def test_named_object(self):
        """Test named object address derivation."""
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "f417184602a828a3819edf5e36285ebef5e4db1ba36270be580d6fd2d7bcc321"
        )
        actual = AccountAddress.for_named_object(base_address, b"bob's collection")
        assert actual == expected

    def test_collection(self):
        """Test collection address derivation."""
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "f417184602a828a3819edf5e36285ebef5e4db1ba36270be580d6fd2d7bcc321"
        )
        actual = AccountAddress.for_named_collection(base_address, "bob's collection")
        assert actual == expected

    def test_token(self):
        """Test token address derivation."""
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "e20d1f22a5400ba7be0f515b7cbd00edc42dbcc31acc01e31128b2b5ddb3c56e"
        )
        actual = AccountAddress.for_named_token(
            base_address, "bob's collection", "bob's token"
        )
        assert actual == expected


class TestAddressFormatting:
    """Tests for address string formatting."""

    def test_special_address_0x0(self):
        """Test special address 0x0 formatting."""
        assert (
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                )
            )
            == "0x0"
        )

    def test_special_address_0x1(self):
        """Test special address 0x1 formatting."""
        assert (
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                )
            )
            == "0x1"
        )

    def test_special_address_0x4(self):
        """Test special address 0x4 formatting."""
        assert (
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000004"
                )
            )
            == "0x4"
        )

    def test_special_address_0xf(self):
        """Test special address 0xf formatting."""
        assert (
            str(
                AccountAddress.from_str_relaxed(
                    "0x000000000000000000000000000000000000000000000000000000000000000f"
                )
            )
            == "0xf"
        )

    def test_special_address_from_short(self):
        """Test special address from short format."""
        assert str(AccountAddress.from_str_relaxed("d")) == "0xd"

    def test_non_special_address_keeps_padding(self):
        """Test non-special addresses keep their full padding."""
        value = "0x0000000000000000000000000000000000000000000000000000000000000010"
        assert str(AccountAddress.from_str_relaxed(value)) == value


class TestFromStrRelaxed:
    """Tests for relaxed address parsing."""

    def test_zero_all_formats(self):
        """Test all formats accepted for 0x0."""
        assert (
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.longWith0x))
            == ADDRESS_ZERO.shortWith0x
        )
        assert (
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.longWithout0x))
            == ADDRESS_ZERO.shortWith0x
        )
        assert (
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.shortWith0x))
            == ADDRESS_ZERO.shortWith0x
        )
        assert (
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.shortWithout0x))
            == ADDRESS_ZERO.shortWith0x
        )

    def test_f_all_formats(self):
        """Test all formats accepted for 0xf."""
        assert (
            str(AccountAddress.from_str_relaxed(ADDRESS_F.longWith0x))
            == ADDRESS_F.shortWith0x
        )
        assert (
            str(AccountAddress.from_str_relaxed(ADDRESS_F.longWithout0x))
            == ADDRESS_F.shortWith0x
        )
        assert (
            str(AccountAddress.from_str_relaxed(ADDRESS_F.shortWith0x))
            == ADDRESS_F.shortWith0x
        )
        assert (
            str(AccountAddress.from_str_relaxed(ADDRESS_F.shortWithout0x))
            == ADDRESS_F.shortWith0x
        )


class TestFromStrStrict:
    """Tests for strict address parsing."""

    def test_zero_requires_prefix(self):
        """Test 0x0 requires 0x prefix in strict mode."""
        assert (
            str(AccountAddress.from_str(ADDRESS_ZERO.longWith0x))
            == ADDRESS_ZERO.shortWith0x
        )
        with pytest.raises(RuntimeError):
            AccountAddress.from_str(ADDRESS_ZERO.longWithout0x)
        assert (
            str(AccountAddress.from_str(ADDRESS_ZERO.shortWith0x))
            == ADDRESS_ZERO.shortWith0x
        )
        with pytest.raises(RuntimeError):
            AccountAddress.from_str(ADDRESS_ZERO.shortWithout0x)

    def test_padded_short_form_rejected(self):
        """Test padded short form like 0x0f is rejected."""
        with pytest.raises(RuntimeError):
            AccountAddress.from_str(ADDRESS_F_PADDED_SHORT_FORM.shortWith0x)
        with pytest.raises(RuntimeError):
            AccountAddress.from_str(ADDRESS_F_PADDED_SHORT_FORM.shortWithout0x)

    def test_non_special_requires_long_format(self):
        """Test non-special addresses require long format."""
        assert (
            str(AccountAddress.from_str(ADDRESS_TEN.longWith0x))
            == ADDRESS_TEN.longWith0x
        )
        with pytest.raises(RuntimeError):
            AccountAddress.from_str(ADDRESS_TEN.longWithout0x)
        with pytest.raises(RuntimeError):
            AccountAddress.from_str(ADDRESS_TEN.shortWith0x)
        with pytest.raises(RuntimeError):
            AccountAddress.from_str(ADDRESS_TEN.shortWithout0x)

