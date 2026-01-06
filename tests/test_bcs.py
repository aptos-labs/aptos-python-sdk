# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for BCS (Binary Canonical Serialization) module.

These tests verify the serialization and deserialization of various data types
according to the BCS specification.
"""

import pytest
from aptos_sdk.bcs import Deserializer, Serializer


class TestBool:
    """Tests for boolean serialization."""

    def test_bool_true(self, serializer):
        in_value = True
        serializer.bool(in_value)
        der = Deserializer(serializer.output())
        out_value = der.bool()
        assert in_value == out_value

    def test_bool_false(self, serializer):
        in_value = False
        serializer.bool(in_value)
        der = Deserializer(serializer.output())
        out_value = der.bool()
        assert in_value == out_value

    def test_bool_error(self, serializer):
        serializer.u8(32)
        der = Deserializer(serializer.output())
        with pytest.raises(Exception):
            der.bool()


class TestBytes:
    """Tests for byte array serialization."""

    def test_bytes(self, serializer):
        in_value = b"1234567890"
        serializer.to_bytes(in_value)
        der = Deserializer(serializer.output())
        out_value = der.to_bytes()
        assert in_value == out_value


class TestCollections:
    """Tests for map and sequence serialization."""

    def test_map(self, serializer):
        in_value = {"a": 12345, "b": 99234, "c": 23829}
        serializer.map(in_value, Serializer.str, Serializer.u32)
        der = Deserializer(serializer.output())
        out_value = der.map(Deserializer.str, Deserializer.u32)
        assert in_value == out_value

    def test_sequence(self, serializer):
        in_value = ["a", "abc", "def", "ghi"]
        serializer.sequence(in_value, Serializer.str)
        der = Deserializer(serializer.output())
        out_value = der.sequence(Deserializer.str)
        assert in_value == out_value

    def test_sequence_serializer(self, serializer):
        in_value = ["a", "abc", "def", "ghi"]
        seq_ser = Serializer.sequence_serializer(Serializer.str)
        seq_ser(serializer, in_value)
        der = Deserializer(serializer.output())
        out_value = der.sequence(Deserializer.str)
        assert in_value == out_value


class TestString:
    """Tests for string serialization."""

    def test_str(self, serializer):
        in_value = "1234567890"
        serializer.str(in_value)
        der = Deserializer(serializer.output())
        out_value = der.str()
        assert in_value == out_value


class TestIntegers:
    """Tests for integer serialization."""

    def test_u8(self, serializer):
        in_value = 15
        serializer.u8(in_value)
        der = Deserializer(serializer.output())
        out_value = der.u8()
        assert in_value == out_value

    def test_u16(self, serializer):
        in_value = 11115
        serializer.u16(in_value)
        der = Deserializer(serializer.output())
        out_value = der.u16()
        assert in_value == out_value

    def test_u32(self, serializer):
        in_value = 1111111115
        serializer.u32(in_value)
        der = Deserializer(serializer.output())
        out_value = der.u32()
        assert in_value == out_value

    def test_u64(self, serializer):
        in_value = 1111111111111111115
        serializer.u64(in_value)
        der = Deserializer(serializer.output())
        out_value = der.u64()
        assert in_value == out_value

    def test_u128(self, serializer):
        in_value = 1111111111111111111111111111111111115
        serializer.u128(in_value)
        der = Deserializer(serializer.output())
        out_value = der.u128()
        assert in_value == out_value

    def test_u256(self, serializer):
        in_value = (
            111111111111111111111111111111111111111111111111111111111111111111111111111115
        )
        serializer.u256(in_value)
        der = Deserializer(serializer.output())
        out_value = der.u256()
        assert in_value == out_value

    def test_uleb128(self, serializer):
        in_value = 1111111115
        serializer.uleb128(in_value)
        der = Deserializer(serializer.output())
        out_value = der.uleb128()
        assert in_value == out_value

