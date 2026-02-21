# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.type_tag — TypeTag, StructTag, MoveModuleId, and all primitive tags.
"""

import pytest

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.errors import (
    InvalidModuleIdError,
    InvalidStructTagError,
    InvalidTypeTagError,
)
from aptos_sdk.type_tag import (
    AccountAddressTag,
    BoolTag,
    MoveModuleId,
    SignerTag,
    StructTag,
    TypeTag,
    TypeTagVariant,
    U8Tag,
    U16Tag,
    U32Tag,
    U64Tag,
    U128Tag,
    U256Tag,
    VectorTag,
)

# ---------------------------------------------------------------------------
# TypeTagVariant
# ---------------------------------------------------------------------------


class TestTypeTagVariant:
    def test_bool_variant_value(self):
        assert TypeTagVariant.BOOL == 0

    def test_u8_variant_value(self):
        assert TypeTagVariant.U8 == 1

    def test_u64_variant_value(self):
        assert TypeTagVariant.U64 == 2

    def test_u128_variant_value(self):
        assert TypeTagVariant.U128 == 3

    def test_address_variant_value(self):
        assert TypeTagVariant.ADDRESS == 4

    def test_signer_variant_value(self):
        assert TypeTagVariant.SIGNER == 5

    def test_vector_variant_value(self):
        assert TypeTagVariant.VECTOR == 6

    def test_struct_variant_value(self):
        assert TypeTagVariant.STRUCT == 7

    def test_u16_variant_value(self):
        assert TypeTagVariant.U16 == 8

    def test_u32_variant_value(self):
        assert TypeTagVariant.U32 == 9

    def test_u256_variant_value(self):
        assert TypeTagVariant.U256 == 10


# ---------------------------------------------------------------------------
# Primitive tags
# ---------------------------------------------------------------------------


class TestPrimitiveTags:
    def test_bool_tag_variant(self):
        tag = BoolTag()
        assert tag.variant() == TypeTagVariant.BOOL

    def test_bool_tag_str(self):
        assert str(BoolTag()) == "bool"

    def test_u8_tag_str(self):
        assert str(U8Tag()) == "u8"

    def test_u16_tag_str(self):
        assert str(U16Tag()) == "u16"

    def test_u32_tag_str(self):
        assert str(U32Tag()) == "u32"

    def test_u64_tag_str(self):
        assert str(U64Tag()) == "u64"

    def test_u128_tag_str(self):
        assert str(U128Tag()) == "u128"

    def test_u256_tag_str(self):
        assert str(U256Tag()) == "u256"

    def test_address_tag_str(self):
        assert str(AccountAddressTag()) == "address"

    def test_signer_tag_str(self):
        assert str(SignerTag()) == "signer"

    def test_bool_tag_equality(self):
        assert BoolTag() == BoolTag()

    def test_u8_tag_equality(self):
        assert U8Tag() == U8Tag()

    def test_different_tags_not_equal(self):
        assert BoolTag() != U8Tag()

    def test_primitive_tags_have_correct_variants(self):
        assert U8Tag().variant() == TypeTagVariant.U8
        assert U16Tag().variant() == TypeTagVariant.U16
        assert U32Tag().variant() == TypeTagVariant.U32
        assert U64Tag().variant() == TypeTagVariant.U64
        assert U128Tag().variant() == TypeTagVariant.U128
        assert U256Tag().variant() == TypeTagVariant.U256
        assert AccountAddressTag().variant() == TypeTagVariant.ADDRESS
        assert SignerTag().variant() == TypeTagVariant.SIGNER


# ---------------------------------------------------------------------------
# TypeTag wrapper
# ---------------------------------------------------------------------------


class TestTypeTag:
    def test_wraps_bool_tag(self):
        tag = TypeTag(BoolTag())
        assert str(tag) == "bool"

    def test_wraps_u64_tag(self):
        tag = TypeTag(U64Tag())
        assert str(tag) == "u64"

    def test_equality_same_inner(self):
        assert TypeTag(BoolTag()) == TypeTag(BoolTag())

    def test_equality_different_inner(self):
        assert TypeTag(BoolTag()) != TypeTag(U8Tag())

    def test_not_equal_to_non_typetag(self):
        result = TypeTag(BoolTag()).__eq__("not a tag")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# VectorTag
# ---------------------------------------------------------------------------


class TestVectorTag:
    def test_vector_u8_str(self):
        tag = VectorTag(TypeTag(U8Tag()))
        assert str(tag) == "vector<u8>"

    def test_vector_bool_str(self):
        tag = VectorTag(TypeTag(BoolTag()))
        assert str(tag) == "vector<bool>"

    def test_nested_vector_str(self):
        inner = TypeTag(VectorTag(TypeTag(U8Tag())))
        outer = VectorTag(inner)
        assert str(outer) == "vector<vector<u8>>"

    def test_vector_variant(self):
        tag = VectorTag(TypeTag(U8Tag()))
        assert tag.variant() == TypeTagVariant.VECTOR

    def test_vector_equality(self):
        a = VectorTag(TypeTag(U8Tag()))
        b = VectorTag(TypeTag(U8Tag()))
        assert a == b

    def test_vector_inequality(self):
        a = VectorTag(TypeTag(U8Tag()))
        b = VectorTag(TypeTag(BoolTag()))
        assert a != b


# ---------------------------------------------------------------------------
# StructTag
# ---------------------------------------------------------------------------


class TestStructTag:
    def _make_struct_tag(
        self,
        address: str = "0x1",
        module: str = "coin",
        name: str = "CoinStore",
        type_args=None,
    ) -> StructTag:
        if type_args is None:
            type_args = []
        return StructTag(
            AccountAddress.from_str_relaxed(address), module, name, type_args
        )

    def test_str_no_type_args(self):
        tag = self._make_struct_tag()
        assert str(tag) == "0x1::coin::CoinStore"

    def test_str_with_type_arg(self):
        inner = TypeTag(
            StructTag(
                AccountAddress.from_str_relaxed("0x1"),
                "aptos_coin",
                "AptosCoin",
                [],
            )
        )
        tag = StructTag(
            AccountAddress.from_str_relaxed("0x1"), "coin", "CoinStore", [inner]
        )
        assert str(tag) == "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"

    def test_str_with_multiple_type_args(self):
        arg1 = TypeTag(U64Tag())
        arg2 = TypeTag(BoolTag())
        tag = StructTag(
            AccountAddress.from_str_relaxed("0x1"), "foo", "Bar", [arg1, arg2]
        )
        assert str(tag) == "0x1::foo::Bar<u64, bool>"

    def test_equality(self):
        a = self._make_struct_tag()
        b = self._make_struct_tag()
        assert a == b

    def test_inequality_module(self):
        a = self._make_struct_tag(module="coin")
        b = self._make_struct_tag(module="token")
        assert a != b

    def test_from_str_simple(self):
        tag = StructTag.from_str("0x1::aptos_coin::AptosCoin")
        assert tag.module == "aptos_coin"
        assert tag.name == "AptosCoin"
        assert str(tag.address) == "0x1"
        assert tag.type_args == []

    def test_from_str_with_generic(self):
        tag = StructTag.from_str("0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")
        assert tag.module == "coin"
        assert tag.name == "CoinStore"
        assert len(tag.type_args) == 1

    def test_from_str_invalid_raises(self):
        with pytest.raises(InvalidStructTagError):
            StructTag.from_str("not_a_struct_tag")

    def test_from_str_trailing_chars_raises(self):
        with pytest.raises(InvalidStructTagError):
            StructTag.from_str("0x1::coin::CoinStore extra")

    def test_variant_is_struct(self):
        tag = self._make_struct_tag()
        assert tag.variant() == TypeTagVariant.STRUCT


# ---------------------------------------------------------------------------
# TypeTag.from_str — primitives
# ---------------------------------------------------------------------------


class TestTypeTagFromStr:
    def test_bool(self):
        tag = TypeTag.from_str("bool")
        assert str(tag) == "bool"

    def test_u8(self):
        assert str(TypeTag.from_str("u8")) == "u8"

    def test_u16(self):
        assert str(TypeTag.from_str("u16")) == "u16"

    def test_u32(self):
        assert str(TypeTag.from_str("u32")) == "u32"

    def test_u64(self):
        assert str(TypeTag.from_str("u64")) == "u64"

    def test_u128(self):
        assert str(TypeTag.from_str("u128")) == "u128"

    def test_u256(self):
        assert str(TypeTag.from_str("u256")) == "u256"

    def test_address(self):
        assert str(TypeTag.from_str("address")) == "address"

    def test_signer(self):
        assert str(TypeTag.from_str("signer")) == "signer"

    def test_vector_u8(self):
        tag = TypeTag.from_str("vector<u8>")
        assert str(tag) == "vector<u8>"

    def test_nested_vector(self):
        tag = TypeTag.from_str("vector<vector<u8>>")
        assert str(tag) == "vector<vector<u8>>"

    def test_struct(self):
        tag = TypeTag.from_str("0x1::aptos_coin::AptosCoin")
        assert str(tag) == "0x1::aptos_coin::AptosCoin"

    def test_struct_with_generic(self):
        tag = TypeTag.from_str("0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")
        assert str(tag) == "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"

    def test_multiple_generics(self):
        tag = TypeTag.from_str("0x1::foo::Bar<u64, bool>")
        assert str(tag) == "0x1::foo::Bar<u64, bool>"

    def test_whitespace_tolerated(self):
        tag = TypeTag.from_str("  bool  ")
        assert str(tag) == "bool"

    def test_invalid_type_raises(self):
        with pytest.raises(InvalidTypeTagError):
            TypeTag.from_str("not_a_type")

    def test_trailing_chars_raise(self):
        with pytest.raises(InvalidTypeTagError):
            TypeTag.from_str("bool extra")

    def test_deeply_nested_generic(self):
        s = "0x1::coin::CoinStore<0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>>"
        tag = TypeTag.from_str(s)
        assert str(tag) == s


# ---------------------------------------------------------------------------
# BCS round-trips
# ---------------------------------------------------------------------------


class TestBcsRoundTrips:
    def _bcs_round_trip(self, tag: TypeTag) -> TypeTag:
        ser = Serializer()
        tag.serialize(ser)
        der = Deserializer(ser.output())
        return TypeTag.deserialize(der)

    def test_bool_round_trip(self):
        original = TypeTag(BoolTag())
        assert self._bcs_round_trip(original) == original

    def test_u8_round_trip(self):
        original = TypeTag(U8Tag())
        assert self._bcs_round_trip(original) == original

    def test_u16_round_trip(self):
        assert self._bcs_round_trip(TypeTag(U16Tag())) == TypeTag(U16Tag())

    def test_u64_round_trip(self):
        assert self._bcs_round_trip(TypeTag(U64Tag())) == TypeTag(U64Tag())

    def test_u128_round_trip(self):
        assert self._bcs_round_trip(TypeTag(U128Tag())) == TypeTag(U128Tag())

    def test_u256_round_trip(self):
        assert self._bcs_round_trip(TypeTag(U256Tag())) == TypeTag(U256Tag())

    def test_address_round_trip(self):
        assert self._bcs_round_trip(TypeTag(AccountAddressTag())) == TypeTag(
            AccountAddressTag()
        )

    def test_signer_round_trip(self):
        assert self._bcs_round_trip(TypeTag(SignerTag())) == TypeTag(SignerTag())

    def test_vector_round_trip(self):
        original = TypeTag(VectorTag(TypeTag(U8Tag())))
        assert self._bcs_round_trip(original) == original

    def test_struct_round_trip(self):
        original = TypeTag(
            StructTag(
                AccountAddress.from_str_relaxed("0x1"), "aptos_coin", "AptosCoin", []
            )
        )
        assert self._bcs_round_trip(original) == original

    def test_struct_with_generic_round_trip(self):
        inner = TypeTag(
            StructTag(
                AccountAddress.from_str_relaxed("0x1"), "aptos_coin", "AptosCoin", []
            )
        )
        original = TypeTag(
            StructTag(
                AccountAddress.from_str_relaxed("0x1"), "coin", "CoinStore", [inner]
            )
        )
        assert self._bcs_round_trip(original) == original

    def test_unknown_variant_raises(self):
        # Serialize a ULEB128 with an unknown variant (e.g. 255)
        ser = Serializer()
        ser.uleb128(255)
        der = Deserializer(ser.output())
        with pytest.raises(InvalidTypeTagError):
            TypeTag.deserialize(der)


# ---------------------------------------------------------------------------
# MoveModuleId
# ---------------------------------------------------------------------------


class TestMoveModuleId:
    def test_str(self):
        module = MoveModuleId(AccountAddress.from_str_relaxed("0x1"), "coin")
        assert str(module) == "0x1::coin"

    def test_equality(self):
        a = MoveModuleId(AccountAddress.ONE, "coin")
        b = MoveModuleId(AccountAddress.ONE, "coin")
        assert a == b

    def test_from_str(self):
        module = MoveModuleId.from_str("0x1::aptos_account")
        assert module.name == "aptos_account"
        assert module.address == AccountAddress.ONE

    def test_from_str_invalid_format(self):
        with pytest.raises(InvalidModuleIdError):
            MoveModuleId.from_str("no_double_colon")

    def test_from_str_empty_module(self):
        with pytest.raises(InvalidModuleIdError):
            MoveModuleId.from_str("0x1::")

    def test_bcs_round_trip(self):
        original = MoveModuleId(AccountAddress.ONE, "coin")
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = MoveModuleId.deserialize(der)
        assert restored == original
