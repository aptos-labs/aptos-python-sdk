"""Unit tests for ChainId."""

from aptos_sdk_v2.bcs import Deserializer, Serializer
from aptos_sdk_v2.types.chain_id import ChainId


class TestChainId:
    def test_value(self):
        assert ChainId(4).value == 4

    def test_eq(self):
        assert ChainId(4) == ChainId(4)
        assert ChainId(4) != ChainId(5)

    def test_serialize_round_trip(self):
        cid = ChainId(157)
        ser = Serializer()
        cid.serialize(ser)
        result = ChainId.deserialize(Deserializer(ser.output()))
        assert cid == result

    def test_invalid_value_raises(self):
        import pytest

        with pytest.raises(ValueError):
            ChainId(256)

    def test_constants(self):
        assert ChainId.MAINNET.value == 1
        assert ChainId.TESTNET.value == 2
