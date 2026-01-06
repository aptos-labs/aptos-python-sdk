# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for TypeTag and StructTag module.
"""

import pytest
from aptos_sdk.type_tag import StructTag, TypeTag


class TestStructTag:
    """Tests for StructTag parsing and serialization."""

    def test_nested_structs(self):
        """Test parsing and serialization of nested struct tags."""
        l0 = "0x0::l0::L0"
        l10 = "0x1::l10::L10"
        l20 = "0x2::l20::L20"
        l11 = "0x1::l11::L11"
        composite = f"{l0}<{l10}<{l20}>, {l11}>"

        derived = StructTag.from_str(composite)
        assert composite == f"{derived}"

        in_bytes = derived.to_bytes()
        from_bytes = StructTag.from_bytes(in_bytes)
        assert derived == from_bytes

    def test_simple_struct_tag(self):
        """Test simple struct tag without type parameters."""
        tag = StructTag.from_str("0x1::aptos_coin::AptosCoin")
        assert str(tag) == "0x1::aptos_coin::AptosCoin"

    def test_struct_tag_with_single_type_param(self):
        """Test struct tag with single type parameter."""
        tag = StructTag.from_str("0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")
        assert str(tag) == "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"

    def test_struct_tag_bytes_roundtrip(self):
        """Test struct tag serialization round-trip."""
        original = StructTag.from_str("0x1::aptos_coin::AptosCoin")
        in_bytes = original.to_bytes()
        restored = StructTag.from_bytes(in_bytes)
        assert original == restored


class TestTypeTag:
    """Tests for TypeTag wrapping."""

    def test_type_tag_from_struct(self):
        """Test TypeTag creation from StructTag."""
        struct = StructTag.from_str("0x1::aptos_coin::AptosCoin")
        type_tag = TypeTag(struct)
        assert type_tag.value == struct

