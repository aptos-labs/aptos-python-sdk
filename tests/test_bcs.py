# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for aptos_sdk.bcs — BCS Serializer and Deserializer."""

import pytest

from aptos_sdk.bcs import (
    MAX_U8,
    MAX_U16,
    MAX_U32,
    MAX_U64,
    MAX_U128,
    MAX_U256,
    Deserializer,
    Serializer,
)
from aptos_sdk.errors import BcsError

# ---------------------------------------------------------------------------
# Helper: a minimal Serializable struct for struct() tests
# ---------------------------------------------------------------------------


class _Point:
    def __init__(self, x: int, y: int) -> None:
        self.x = x
        self.y = y

    def serialize(self, serializer: Serializer) -> None:
        serializer.u32(self.x)
        serializer.u32(self.y)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "_Point":
        x = deserializer.u32()
        y = deserializer.u32()
        return _Point(x, y)


# ---------------------------------------------------------------------------
# Serializer tests
# ---------------------------------------------------------------------------


class TestSerializerBool:
    def test_true(self):
        s = Serializer()
        s.bool(True)
        assert s.output() == b"\x01"

    def test_false(self):
        s = Serializer()
        s.bool(False)
        assert s.output() == b"\x00"


class TestSerializerIntegers:
    def test_u8_zero(self):
        s = Serializer()
        s.u8(0)
        assert s.output() == b"\x00"

    def test_u8_max(self):
        s = Serializer()
        s.u8(MAX_U8)
        assert s.output() == b"\xff"

    def test_u8_overflow_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u8(256)

    def test_u8_negative_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u8(-1)

    def test_u16_value(self):
        s = Serializer()
        s.u16(0x0102)
        assert s.output() == b"\x02\x01"  # little-endian

    def test_u16_max(self):
        s = Serializer()
        s.u16(MAX_U16)
        assert s.output() == b"\xff\xff"

    def test_u32_value(self):
        s = Serializer()
        s.u32(1)
        assert s.output() == b"\x01\x00\x00\x00"

    def test_u32_max(self):
        s = Serializer()
        s.u32(MAX_U32)
        assert s.output() == b"\xff" * 4

    def test_u64_value(self):
        s = Serializer()
        s.u64(42)
        expected = (42).to_bytes(8, "little")
        assert s.output() == expected

    def test_u64_max(self):
        s = Serializer()
        s.u64(MAX_U64)
        assert s.output() == b"\xff" * 8

    def test_u64_overflow_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u64(MAX_U64 + 1)

    def test_u128_value(self):
        s = Serializer()
        s.u128(1)
        expected = (1).to_bytes(16, "little")
        assert s.output() == expected

    def test_u128_max(self):
        s = Serializer()
        s.u128(MAX_U128)
        assert s.output() == b"\xff" * 16

    def test_u256_value(self):
        s = Serializer()
        s.u256(1)
        expected = (1).to_bytes(32, "little")
        assert s.output() == expected

    def test_u256_max(self):
        s = Serializer()
        s.u256(MAX_U256)
        assert s.output() == b"\xff" * 32


class TestSerializerStrings:
    def test_empty_string(self):
        s = Serializer()
        s.str("")
        assert s.output() == b"\x00"  # ULEB128(0)

    def test_hello(self):
        s = Serializer()
        s.str("hello")
        assert s.output() == b"\x05hello"  # ULEB128(5) + "hello"

    def test_unicode(self):
        s = Serializer()
        s.str("\u00e9")  # é = 2 bytes in UTF-8
        data = s.output()
        assert data[0] == 2  # ULEB128(2)


class TestSerializerBytes:
    def test_empty_bytes(self):
        s = Serializer()
        s.to_bytes(b"")
        assert s.output() == b"\x00"

    def test_some_bytes(self):
        s = Serializer()
        s.to_bytes(b"\xde\xad")
        assert s.output() == b"\x02\xde\xad"

    def test_fixed_bytes(self):
        s = Serializer()
        s.fixed_bytes(b"\x01\x02\x03")
        assert s.output() == b"\x01\x02\x03"


class TestSerializerOption:
    def test_none(self):
        s = Serializer()
        s.option(None, Serializer.u32)
        assert s.output() == b"\x00"

    def test_some(self):
        s = Serializer()
        s.option(42, Serializer.u32)
        expected = b"\x01" + (42).to_bytes(4, "little")
        assert s.output() == expected


class TestSerializerVariantIndex:
    def test_zero(self):
        s = Serializer()
        s.variant_index(0)
        assert s.output() == b"\x00"

    def test_small(self):
        s = Serializer()
        s.variant_index(4)
        assert s.output() == b"\x04"

    def test_negative_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.variant_index(-1)


class TestSerializerUleb128:
    def test_zero(self):
        s = Serializer()
        s.uleb128(0)
        assert s.output() == b"\x00"

    def test_one(self):
        s = Serializer()
        s.uleb128(1)
        assert s.output() == b"\x01"

    def test_127(self):
        s = Serializer()
        s.uleb128(127)
        assert s.output() == b"\x7f"

    def test_128(self):
        s = Serializer()
        s.uleb128(128)
        assert s.output() == b"\x80\x01"

    def test_300(self):
        s = Serializer()
        s.uleb128(300)
        # 300 = 0b100101100 → low 7: 0101100 = 0x2C | 0x80 = 0xAC, high: 0b10 = 0x02
        assert s.output() == b"\xac\x02"


class TestSerializerStruct:
    def test_struct(self):
        s = Serializer()
        s.struct(_Point(10, 20))
        expected = (10).to_bytes(4, "little") + (20).to_bytes(4, "little")
        assert s.output() == expected


class TestSerializerSequence:
    def test_empty_sequence(self):
        s = Serializer()
        s.sequence([], Serializer.u32)
        assert s.output() == b"\x00"

    def test_sequence_of_u32(self):
        s = Serializer()
        s.sequence([1, 2, 3], Serializer.u32)
        data = s.output()
        assert data[0] == 3  # count
        d = Deserializer(data)
        result = d.sequence(Deserializer.u32)
        assert result == [1, 2, 3]


class TestSerializerMap:
    def test_empty_map(self):
        s = Serializer()
        s.map({}, Serializer.str, Serializer.u64)
        assert s.output() == b"\x00"

    def test_map_round_trip(self):
        original = {"a": 1, "b": 2}
        s = Serializer()
        s.map(original, Serializer.str, Serializer.u64)
        d = Deserializer(s.output())
        restored = d.map(Deserializer.str, Deserializer.u64)
        assert restored == original


# ---------------------------------------------------------------------------
# Deserializer tests
# ---------------------------------------------------------------------------


class TestDeserializerBool:
    def test_false(self):
        d = Deserializer(b"\x00")
        assert d.bool() is False

    def test_true(self):
        d = Deserializer(b"\x01")
        assert d.bool() is True

    def test_invalid_raises(self):
        d = Deserializer(b"\x02")
        with pytest.raises(BcsError):
            d.bool()


class TestDeserializerIntegers:
    def test_u8(self):
        d = Deserializer(b"\xff")
        assert d.u8() == 255

    def test_u16(self):
        d = Deserializer(b"\x02\x01")
        assert d.u16() == 0x0102

    def test_u32(self):
        d = Deserializer(b"\x01\x00\x00\x00")
        assert d.u32() == 1

    def test_u64(self):
        d = Deserializer((42).to_bytes(8, "little"))
        assert d.u64() == 42

    def test_u128(self):
        d = Deserializer((999).to_bytes(16, "little"))
        assert d.u128() == 999

    def test_u256(self):
        val = 2**200
        d = Deserializer(val.to_bytes(32, "little"))
        assert d.u256() == val


class TestDeserializerStrings:
    def test_empty_string(self):
        d = Deserializer(b"\x00")
        assert d.str() == ""

    def test_hello(self):
        d = Deserializer(b"\x05hello")
        assert d.str() == "hello"


class TestDeserializerBytes:
    def test_empty(self):
        d = Deserializer(b"\x00")
        assert d.to_bytes() == b""

    def test_some_bytes(self):
        d = Deserializer(b"\x02\xde\xad")
        assert d.to_bytes() == b"\xde\xad"

    def test_fixed_bytes(self):
        d = Deserializer(b"\x01\x02\x03")
        assert d.fixed_bytes(3) == b"\x01\x02\x03"


class TestDeserializerStruct:
    def test_struct(self):
        data = (10).to_bytes(4, "little") + (20).to_bytes(4, "little")
        d = Deserializer(data)
        p = d.struct(_Point)
        assert p.x == 10
        assert p.y == 20


class TestDeserializerRemaining:
    def test_remaining(self):
        d = Deserializer(b"\x01\x02\x03")
        assert d.remaining() == 3
        d.u8()
        assert d.remaining() == 2


class TestDeserializerOption:
    def test_none(self):
        d = Deserializer(b"\x00")
        assert d.option(Deserializer.u32) is None

    def test_some(self):
        data = b"\x01" + (42).to_bytes(4, "little")
        d = Deserializer(data)
        assert d.option(Deserializer.u32) == 42


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_bool_round_trip(self):
        for val in [True, False]:
            s = Serializer()
            s.bool(val)
            d = Deserializer(s.output())
            assert d.bool() == val

    @pytest.mark.parametrize("val", [0, 1, 127, 128, MAX_U8])
    def test_u8_round_trip(self, val):
        s = Serializer()
        s.u8(val)
        d = Deserializer(s.output())
        assert d.u8() == val

    @pytest.mark.parametrize("val", [0, 1, 1000, MAX_U16])
    def test_u16_round_trip(self, val):
        s = Serializer()
        s.u16(val)
        d = Deserializer(s.output())
        assert d.u16() == val

    @pytest.mark.parametrize("val", [0, 1, 100000, MAX_U32])
    def test_u32_round_trip(self, val):
        s = Serializer()
        s.u32(val)
        d = Deserializer(s.output())
        assert d.u32() == val

    @pytest.mark.parametrize("val", [0, 1, 10**18, MAX_U64])
    def test_u64_round_trip(self, val):
        s = Serializer()
        s.u64(val)
        d = Deserializer(s.output())
        assert d.u64() == val

    @pytest.mark.parametrize("val", [0, 1, 10**30, MAX_U128])
    def test_u128_round_trip(self, val):
        s = Serializer()
        s.u128(val)
        d = Deserializer(s.output())
        assert d.u128() == val

    @pytest.mark.parametrize("val", [0, 1, 10**60, MAX_U256])
    def test_u256_round_trip(self, val):
        s = Serializer()
        s.u256(val)
        d = Deserializer(s.output())
        assert d.u256() == val

    def test_str_round_trip(self):
        for val in ["", "hello", "unicode: \u00e9\u00fc"]:
            s = Serializer()
            s.str(val)
            d = Deserializer(s.output())
            assert d.str() == val

    def test_bytes_round_trip(self):
        for val in [b"", b"\x00", b"\xde\xad\xbe\xef"]:
            s = Serializer()
            s.to_bytes(val)
            d = Deserializer(s.output())
            assert d.to_bytes() == val

    def test_struct_round_trip(self):
        original = _Point(42, 99)
        s = Serializer()
        s.struct(original)
        d = Deserializer(s.output())
        restored = d.struct(_Point)
        assert restored.x == 42
        assert restored.y == 99

    def test_multiple_values(self):
        s = Serializer()
        s.u64(123)
        s.str("abc")
        s.bool(True)
        d = Deserializer(s.output())
        assert d.u64() == 123
        assert d.str() == "abc"
        assert d.bool() is True


# ---------------------------------------------------------------------------
# Additional Serializer edge cases
# ---------------------------------------------------------------------------


class TestSerializerEdgeCases:
    def test_u16_negative_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u16(-1)

    def test_u16_overflow_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u16(MAX_U16 + 1)

    def test_u32_negative_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u32(-1)

    def test_u32_overflow_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u32(MAX_U32 + 1)

    def test_u128_negative_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u128(-1)

    def test_u128_overflow_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u128(MAX_U128 + 1)

    def test_u256_negative_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u256(-1)

    def test_u256_overflow_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.u256(MAX_U256 + 1)

    def test_uleb128_negative_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.uleb128(-1)

    def test_uleb128_max_u32_succeeds(self):
        # MAX_U32 is the boundary; it must encode without error
        s = Serializer()
        s.uleb128(MAX_U32)
        d = Deserializer(s.output())
        assert d.uleb128() == MAX_U32

    def test_uleb128_exceeds_max_u32_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.uleb128(MAX_U32 + 1)

    def test_variant_index_max_u32_succeeds(self):
        s = Serializer()
        s.variant_index(MAX_U32)
        d = Deserializer(s.output())
        assert d.variant_index() == MAX_U32

    def test_variant_index_overflow_raises(self):
        s = Serializer()
        with pytest.raises(BcsError):
            s.variant_index(MAX_U32 + 1)

    def test_sequence_serializer_factory(self):
        # sequence_serializer returns a callable that serializes a list
        from aptos_sdk.bcs import Serializer

        ser_fn = Serializer.sequence_serializer(Serializer.u64)
        s = Serializer()
        ser_fn(s, [10, 20, 30])
        d = Deserializer(s.output())
        result = d.sequence(Deserializer.u64)
        assert result == [10, 20, 30]


# ---------------------------------------------------------------------------
# Additional Deserializer edge cases
# ---------------------------------------------------------------------------


class TestDeserializerEdgeCases:
    def test_read_truncated_raises(self):
        # Buffer has only 4 bytes; trying to read 8 should raise BcsError
        d = Deserializer(b"\x01\x02\x03\x04")
        with pytest.raises(BcsError):
            d.u64()

    def test_uleb128_overlong_raises(self):
        # Build a 6-byte ULEB128 (more than the 5-byte limit) by hand.
        # Each byte has the continuation bit set except the last.
        overlong = bytes([0x80, 0x80, 0x80, 0x80, 0x80, 0x00])
        d = Deserializer(overlong)
        with pytest.raises(BcsError):
            d.uleb128()

    def test_u16_round_trip_max(self):
        s = Serializer()
        s.u16(MAX_U16)
        d = Deserializer(s.output())
        assert d.u16() == MAX_U16

    def test_u256_round_trip_max(self):
        s = Serializer()
        s.u256(MAX_U256)
        d = Deserializer(s.output())
        assert d.u256() == MAX_U256

    def test_option_invalid_tag_raises(self):
        # Tag byte 0x02 is neither 0x00 nor 0x01
        d = Deserializer(b"\x02")
        with pytest.raises(BcsError):
            d.option(Deserializer.u32)

    def test_fixed_bytes_truncated_raises(self):
        d = Deserializer(b"\x01\x02")
        with pytest.raises(BcsError):
            d.fixed_bytes(5)

    def test_str_invalid_utf8_raises(self):
        # Length-prefix 2 followed by an invalid two-byte UTF-8 sequence
        bad_utf8 = b"\x02\xff\xfe"
        d = Deserializer(bad_utf8)
        with pytest.raises(BcsError):
            d.str()

    def test_variant_index_round_trip(self):
        s = Serializer()
        s.variant_index(7)
        d = Deserializer(s.output())
        assert d.variant_index() == 7


# ---------------------------------------------------------------------------
# encoder helper
# ---------------------------------------------------------------------------


class TestEncoderHelper:
    def test_encoder_u64(self):
        from aptos_sdk.bcs import encoder

        raw = encoder(42, Serializer.u64)
        d = Deserializer(raw)
        assert d.u64() == 42

    def test_encoder_str(self):
        from aptos_sdk.bcs import encoder

        raw = encoder("hello", Serializer.str)
        d = Deserializer(raw)
        assert d.str() == "hello"

    def test_encoder_struct(self):
        from aptos_sdk.bcs import encoder

        p = _Point(3, 7)
        raw = encoder(p, Serializer.struct)
        d = Deserializer(raw)
        restored = d.struct(_Point)
        assert restored.x == 3 and restored.y == 7
