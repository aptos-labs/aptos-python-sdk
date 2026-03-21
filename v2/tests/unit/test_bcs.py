"""Unit tests for BCS serialization/deserialization — ported from v1 test vectors."""

import pytest

from aptos_sdk_v2.bcs import Deserializer, Serializer


class TestBool:
    def test_true(self):
        ser = Serializer()
        ser.bool(True)
        assert Deserializer(ser.output()).bool() is True

    def test_false(self):
        ser = Serializer()
        ser.bool(False)
        assert Deserializer(ser.output()).bool() is False

    def test_invalid_raises(self):
        ser = Serializer()
        ser.u8(32)
        with pytest.raises(Exception):
            Deserializer(ser.output()).bool()


class TestBytes:
    def test_round_trip(self):
        value = b"1234567890"
        ser = Serializer()
        ser.to_bytes(value)
        assert Deserializer(ser.output()).to_bytes() == value


class TestStr:
    def test_round_trip(self):
        value = "1234567890"
        ser = Serializer()
        ser.str(value)
        assert Deserializer(ser.output()).str() == value


class TestIntegers:
    def test_u8(self):
        value = 15
        ser = Serializer()
        ser.u8(value)
        assert Deserializer(ser.output()).u8() == value

    def test_u16(self):
        value = 11115
        ser = Serializer()
        ser.u16(value)
        assert Deserializer(ser.output()).u16() == value

    def test_u32(self):
        value = 1111111115
        ser = Serializer()
        ser.u32(value)
        assert Deserializer(ser.output()).u32() == value

    def test_u64(self):
        value = 1111111111111111115
        ser = Serializer()
        ser.u64(value)
        assert Deserializer(ser.output()).u64() == value

    def test_u128(self):
        value = 1111111111111111111111111111111111115
        ser = Serializer()
        ser.u128(value)
        assert Deserializer(ser.output()).u128() == value

    def test_u256(self):
        value = 111111111111111111111111111111111111111111111111111111111111111111111111111115
        ser = Serializer()
        ser.u256(value)
        assert Deserializer(ser.output()).u256() == value

    def test_uleb128(self):
        value = 1111111115
        ser = Serializer()
        ser.uleb128(value)
        assert Deserializer(ser.output()).uleb128() == value


class TestComposite:
    def test_sequence(self):
        values = ["a", "abc", "def", "ghi"]
        ser = Serializer()
        ser.sequence(values, Serializer.str)
        result = Deserializer(ser.output()).sequence(Deserializer.str)
        assert values == result

    def test_sequence_serializer(self):
        values = ["a", "abc", "def", "ghi"]
        ser = Serializer()
        seq_ser = Serializer.sequence_serializer(Serializer.str)
        seq_ser(ser, values)
        result = Deserializer(ser.output()).sequence(Deserializer.str)
        assert values == result

    def test_map(self):
        values = {"a": 12345, "b": 99234, "c": 23829}
        ser = Serializer()
        ser.map(values, Serializer.str, Serializer.u32)
        result = Deserializer(ser.output()).map(Deserializer.str, Deserializer.u32)
        assert values == result


class TestOverflow:
    def test_u8_overflow(self):
        ser = Serializer()
        with pytest.raises(Exception):
            ser.u8(256)

    def test_u16_overflow(self):
        ser = Serializer()
        with pytest.raises(Exception):
            ser.u16(2**16)

    def test_u32_overflow(self):
        ser = Serializer()
        with pytest.raises(Exception):
            ser.u32(2**32)

    def test_u64_overflow(self):
        ser = Serializer()
        with pytest.raises(Exception):
            ser.u64(2**64)

    def test_u128_overflow(self):
        ser = Serializer()
        with pytest.raises(Exception):
            ser.u128(2**128)

    def test_u256_overflow(self):
        ser = Serializer()
        with pytest.raises(Exception):
            ser.u256(2**256)

    def test_uleb128_overflow(self):
        ser = Serializer()
        with pytest.raises(Exception):
            ser.uleb128(2**32)


class TestDeserializerEOF:
    def test_read_past_end(self):
        der = Deserializer(b"\x01")
        der.u8()
        with pytest.raises(Exception):
            der.u8()

    def test_remaining(self):
        der = Deserializer(b"\x01\x02\x03")
        assert der.remaining() == 3
        der.u8()
        assert der.remaining() == 2


class TestFixedBytes:
    def test_round_trip(self):
        data = b"\xab\xcd\xef\x01\x02\x03"
        ser = Serializer()
        ser.fixed_bytes(data)
        assert Deserializer(ser.output()).fixed_bytes(6) == data


class TestUleb128DeserializeOverflow:
    def test_large_uleb128_raises(self):
        """Force a uleb128 that decodes to > MAX_U32."""
        from aptos_sdk_v2.errors import BcsDeserializationError

        # Encode 5 bytes, all with continuation bit set except last
        # This encodes a value larger than MAX_U32
        data = b"\xff\xff\xff\xff\x1f"
        with pytest.raises(BcsDeserializationError):
            Deserializer(data).uleb128()


class TestProtocols:
    def test_serializable_protocol(self):
        """Test that the Serializable protocol works via explicit ser/deser."""
        from aptos_sdk_v2.types.account_address import AccountAddress

        addr = AccountAddress.from_str("0x1")
        ser = Serializer()
        addr.serialize(ser)
        raw = ser.output()
        assert len(raw) == 32

        restored = AccountAddress.deserialize(Deserializer(raw))
        assert addr == restored

    def test_to_bytes_and_from_bytes_protocols(self):
        """Test Serializable.to_bytes() and Deserializable.from_bytes() defaults."""
        from aptos_sdk_v2.bcs.protocols import Deserializable, Serializable
        from aptos_sdk_v2.types.account_address import AccountAddress

        # Create a concrete class that inherits the protocol defaults
        class TestAddr(Serializable, Deserializable):
            def __init__(self, addr: AccountAddress):
                self._addr = addr

            def serialize(self, serializer: Serializer) -> None:
                self._addr.serialize(serializer)

            @staticmethod
            def deserialize(deserializer: Deserializer) -> "TestAddr":
                return TestAddr(AccountAddress.deserialize(deserializer))

        addr = AccountAddress.from_str("0x1")
        obj = TestAddr(addr)
        raw = obj.to_bytes()
        assert len(raw) == 32

        restored = TestAddr.from_bytes(raw)
        assert restored._addr == addr
