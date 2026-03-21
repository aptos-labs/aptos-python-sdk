"""Unit tests for TypeTag and StructTag parsing/serialization."""

from aptos_sdk_v2.types.type_tag import StructTag, TypeTag


class TestStructTagFromStr:
    def test_simple(self):
        tag = StructTag.from_str("0x1::coin::Coin")
        assert tag.module == "coin"
        assert tag.name == "Coin"
        assert str(tag.address) == "0x1"
        assert tag.type_args == []

    def test_with_type_arg(self):
        tag = StructTag.from_str("0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")
        assert tag.module == "coin"
        assert tag.name == "CoinStore"
        assert len(tag.type_args) == 1
        inner = tag.type_args[0].value
        assert isinstance(inner, StructTag)
        assert inner.module == "aptos_coin"
        assert inner.name == "AptosCoin"

    def test_nested_generics(self):
        l0 = "0x0::l0::L0"
        l10 = "0x1::l10::L10"
        l20 = "0x2::l20::L20"
        l11 = "0x1::l11::L11"
        composite = f"{l0}<{l10}<{l20}>, {l11}>"
        derived = StructTag.from_str(composite)
        assert str(derived) == composite

    def test_round_trip_bcs(self):
        from aptos_sdk_v2.bcs import Deserializer, Serializer

        l0 = "0x0::l0::L0"
        l10 = "0x1::l10::L10"
        l20 = "0x2::l20::L20"
        l11 = "0x1::l11::L11"
        composite = f"{l0}<{l10}<{l20}>, {l11}>"
        derived = StructTag.from_str(composite)
        ser = Serializer()
        derived.serialize(ser)
        der = Deserializer(ser.output())
        from_bcs = StructTag.deserialize(der)
        assert derived == from_bcs


class TestTypeTagSerialization:
    def test_struct_tag_bcs_round_trip(self):
        from aptos_sdk_v2.bcs import Deserializer, Serializer

        tag = TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))
        ser = Serializer()
        tag.serialize(ser)
        der = Deserializer(ser.output())
        result = TypeTag.deserialize(der)
        assert tag == result

    def test_primitive_tags_round_trip(self):
        from aptos_sdk_v2.bcs import Deserializer, Serializer
        from aptos_sdk_v2.types.account_address import AccountAddress
        from aptos_sdk_v2.types.type_tag import (
            AccountAddressTag,
            BoolTag,
            U8Tag,
            U16Tag,
            U32Tag,
            U64Tag,
            U128Tag,
            U256Tag,
        )

        cases = [
            TypeTag(BoolTag(True)),
            TypeTag(U8Tag(42)),
            TypeTag(U16Tag(1000)),
            TypeTag(U32Tag(100_000)),
            TypeTag(U64Tag(10**18)),
            TypeTag(U128Tag(10**30)),
            TypeTag(U256Tag(10**60)),
            TypeTag(AccountAddressTag(AccountAddress.from_str("0x1"))),
        ]
        for tag in cases:
            ser = Serializer()
            tag.serialize(ser)
            result = TypeTag.deserialize(Deserializer(ser.output()))
            assert tag == result, f"Failed for {tag}"

    def test_primitive_tag_str(self):
        from aptos_sdk_v2.types.type_tag import BoolTag, U64Tag

        assert str(BoolTag(True)) == "True"
        assert str(U64Tag(123)) == "123"

    def test_type_tag_eq_ne(self):
        a = TypeTag(StructTag.from_str("0x1::coin::Coin"))
        b = TypeTag(StructTag.from_str("0x1::coin::Coin"))
        c = TypeTag(StructTag.from_str("0x1::coin::Other"))
        assert a == b
        assert a != c
        assert a != "not a tag"

    def test_type_tag_str(self):
        tag = TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))
        assert str(tag) == "0x1::aptos_coin::AptosCoin"

    def test_struct_tag_eq(self):
        a = StructTag.from_str("0x1::coin::Coin")
        b = StructTag.from_str("0x1::coin::Coin")
        assert a == b
        assert a != "not a struct tag"

    def test_each_primitive_deserialize(self):
        """Ensure each TypeTag variant deserializes correctly via individual serialize."""
        from aptos_sdk_v2.bcs import Deserializer, Serializer
        from aptos_sdk_v2.types.type_tag import (
            BoolTag,
            U8Tag,
            U16Tag,
            U32Tag,
            U64Tag,
            U128Tag,
            U256Tag,
        )

        # Test individual primitive tags serialize/deserialize methods
        for tag_class, value, ser_fn, deser_fn in [
            (BoolTag, True, lambda s, v: s.bool(v.value), lambda d: BoolTag(d.bool())),
            (U8Tag, 42, lambda s, v: s.u8(v.value), lambda d: U8Tag(d.u8())),
            (U16Tag, 1000, lambda s, v: s.u16(v.value), lambda d: U16Tag(d.u16())),
            (U32Tag, 100000, lambda s, v: s.u32(v.value), lambda d: U32Tag(d.u32())),
            (U64Tag, 10**15, lambda s, v: s.u64(v.value), lambda d: U64Tag(d.u64())),
            (U128Tag, 10**30, lambda s, v: s.u128(v.value), lambda d: U128Tag(d.u128())),
            (U256Tag, 10**60, lambda s, v: s.u256(v.value), lambda d: U256Tag(d.u256())),
        ]:
            tag = tag_class(value)
            ser = Serializer()
            tag.serialize(ser)
            result = tag_class.deserialize(Deserializer(ser.output()))
            assert tag == result, f"Failed for {tag_class.__name__}"
            assert str(tag) == str(value)

    def test_account_address_tag_direct(self):
        from aptos_sdk_v2.bcs import Deserializer, Serializer
        from aptos_sdk_v2.types.account_address import AccountAddress
        from aptos_sdk_v2.types.type_tag import AccountAddressTag

        addr = AccountAddress.from_str("0x1")
        tag = AccountAddressTag(addr)
        ser = Serializer()
        tag.serialize(ser)
        result = AccountAddressTag.deserialize(Deserializer(ser.output()))
        assert tag == result
        assert str(tag) == "0x1"

    def test_invalid_type_tag_parse(self):
        import pytest

        from aptos_sdk_v2.errors import InvalidTypeTagError

        with pytest.raises(InvalidTypeTagError):
            StructTag.from_str("not_a_valid::tag")

    def test_struct_tag_from_str_non_struct_raises(self):
        import pytest

        from aptos_sdk_v2.errors import InvalidTypeTagError

        # A standalone address without :: should fail
        with pytest.raises(InvalidTypeTagError):
            StructTag.from_str("")

    def test_type_tag_repr(self):
        tag = TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))
        assert repr(tag) == "0x1::aptos_coin::AptosCoin"

    def test_type_tag_unknown_variant_raises(self):
        import pytest

        from aptos_sdk_v2.bcs import Deserializer, Serializer
        from aptos_sdk_v2.errors import InvalidTypeTagError

        ser = Serializer()
        ser.uleb128(99)  # unknown variant
        with pytest.raises(InvalidTypeTagError, match="Unknown TypeTag variant"):
            TypeTag.deserialize(Deserializer(ser.output()))
