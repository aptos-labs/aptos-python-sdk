# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for aptos_sdk.chain_id — ChainId value type."""

import pytest

from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.chain_id import ChainId


class TestChainIdConstruction:
    def test_basic(self):
        cid = ChainId(1)
        assert cid.value == 1

    def test_zero(self):
        cid = ChainId(0)
        assert cid.value == 0

    def test_max_u8(self):
        cid = ChainId(255)
        assert cid.value == 255

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            ChainId(-1)

    def test_over_255_raises(self):
        with pytest.raises(ValueError):
            ChainId(256)

    def test_non_int_raises(self):
        with pytest.raises(TypeError):
            ChainId("1")  # type: ignore[arg-type]


class TestChainIdImmutability:
    def test_cannot_set_attribute(self):
        cid = ChainId(1)
        with pytest.raises(AttributeError):
            cid.value = 2  # type: ignore[misc]

    def test_cannot_add_attribute(self):
        cid = ChainId(1)
        with pytest.raises(AttributeError):
            cid.new_attr = "x"  # type: ignore[attr-defined]


class TestChainIdEquality:
    def test_equal(self):
        assert ChainId(1) == ChainId(1)

    def test_not_equal(self):
        assert ChainId(1) != ChainId(2)

    def test_not_equal_other_type(self):
        assert ChainId(1) != 1

    def test_hash_equal(self):
        assert hash(ChainId(1)) == hash(ChainId(1))

    def test_hash_usable_in_set(self):
        s = {ChainId(1), ChainId(1), ChainId(2)}
        assert len(s) == 2


class TestChainIdBcs:
    def test_serialize(self):
        s = Serializer()
        ChainId(42).serialize(s)
        assert s.output() == bytes([42])

    def test_deserialize(self):
        d = Deserializer(bytes([42]))
        cid = ChainId.deserialize(d)
        assert cid.value == 42

    def test_round_trip(self):
        original = ChainId(100)
        s = Serializer()
        original.serialize(s)
        d = Deserializer(s.output())
        restored = ChainId.deserialize(d)
        assert original == restored

    def test_round_trip_zero(self):
        original = ChainId(0)
        s = Serializer()
        original.serialize(s)
        d = Deserializer(s.output())
        assert ChainId.deserialize(d) == original

    def test_round_trip_max(self):
        original = ChainId(255)
        s = Serializer()
        original.serialize(s)
        d = Deserializer(s.output())
        assert ChainId.deserialize(d) == original
