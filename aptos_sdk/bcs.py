# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Binary Canonical Serialization (BCS) implementation for the Aptos Python SDK.

This module provides a simple BCS serializer and deserializer for encoding and decoding
data in the Binary Canonical Serialization format used throughout the Aptos ecosystem.
BCS is a canonical encoding format that ensures deterministic serialization.

Learn more at https://github.com/diem/bcs

The module contains:
- Protocol interfaces for serializable and deserializable objects
- Deserializer class for reading BCS-encoded data
- Serializer class for writing BCS-encoded data
- Helper functions for encoding values
- Comprehensive test suite

Examples:
    Basic serialization::

        from aptos_sdk.bcs import Serializer, Deserializer

        # Serialize a string
        ser = Serializer()
        ser.str("hello")
        data = ser.output()

        # Deserialize back to string
        der = Deserializer(data)
        result = der.str()  # "hello"

    Working with custom structures::

        class MyStruct:
            def serialize(self, serializer):
                serializer.str(self.name)
                serializer.u32(self.value)

            @staticmethod
            def deserialize(deserializer):
                name = deserializer.str()
                value = deserializer.u32()
                return MyStruct(name, value)
"""

from __future__ import annotations

import io
import typing
import unittest
from typing import Dict, List

from typing_extensions import Protocol

MAX_U8 = 2**8 - 1
MAX_U16 = 2**16 - 1
MAX_U32 = 2**32 - 1
MAX_U64 = 2**64 - 1
MAX_U128 = 2**128 - 1
MAX_U256 = 2**256 - 1


class Deserializable(Protocol):
    """Protocol for objects that can be deserialized from a BCS byte stream.

    This protocol defines the interface that classes must implement to support
    BCS deserialization. Classes implementing this protocol can be automatically
    deserialized from binary data.

    The protocol requires:
    - A `from_bytes` class method that creates an instance from raw bytes
    - A `deserialize` static method that reads from a Deserializer

    Examples:
        Implementing a deserializable class::

            class MyClass:
                def __init__(self, value: str):
                    self.value = value

                @staticmethod
                def deserialize(deserializer: Deserializer) -> 'MyClass':
                    value = deserializer.str()
                    return MyClass(value)

            # Usage
            data = b'\x05hello'  # BCS-encoded string
            obj = MyClass.from_bytes(data)
    """

    @classmethod
    def from_bytes(cls, indata: bytes) -> Deserializable:
        """Create an instance of this class from BCS-encoded bytes.

        Args:
            indata: The BCS-encoded byte data to deserialize.

        Returns:
            An instance of the implementing class.

        Raises:
            Exception: If the data cannot be deserialized or is malformed.
        """
        der = Deserializer(indata)
        return der.struct(cls)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Deserializable:
        """Deserialize an instance from a Deserializer.

        Args:
            deserializer: The Deserializer to read data from.

        Returns:
            A deserialized instance of the implementing class.

        Note:
            This is an abstract method that must be implemented by concrete classes.
        """
        ...


class Serializable(Protocol):
    """Protocol for objects that can be serialized into a BCS byte stream.

    This protocol defines the interface that classes must implement to support
    BCS serialization. Classes implementing this protocol can be automatically
    serialized to binary data.

    The protocol requires:
    - A `to_bytes` method that converts the instance to raw bytes
    - A `serialize` method that writes data to a Serializer

    Examples:
        Implementing a serializable class::

            class MyClass:
                def __init__(self, value: str):
                    self.value = value

                def serialize(self, serializer: Serializer):
                    serializer.str(self.value)

            # Usage
            obj = MyClass("hello")
            data = obj.to_bytes()  # Returns BCS-encoded bytes
    """

    def to_bytes(self) -> bytes:
        """Convert this object to BCS-encoded bytes.

        Returns:
            The BCS-encoded representation of this object as bytes.

        Raises:
            Exception: If the object cannot be serialized.
        """
        ser = Serializer()
        ser.struct(self)
        return ser.output()

    def serialize(self, serializer: Serializer):
        """Serialize this object using the provided Serializer.

        Args:
            serializer: The Serializer to write data to.

        Note:
            This is an abstract method that must be implemented by concrete classes.
        """
        ...


class Deserializer:
    """A BCS deserializer for reading data from a byte stream.

    The Deserializer class provides methods to read various data types from
    BCS-encoded byte data. It maintains an internal position in the byte stream
    and provides methods to read primitive types, collections, and custom structures.

    Attributes:
        _input: Internal BytesIO stream for reading data.
        _length: Total length of the input data.

    Examples:
        Basic usage::

            data = b'\x01\x05hello'  # BCS-encoded bool and string
            der = Deserializer(data)

            flag = der.bool()    # True
            text = der.str()     # "hello"

        Reading collections::

            # Deserialize a sequence of strings
            values = der.sequence(Deserializer.str)

            # Deserialize a map
            mapping = der.map(Deserializer.str, Deserializer.u32)
    """

    _input: io.BytesIO
    _length: int

    def __init__(self, data: bytes):
        """Initialize the deserializer with byte data.

        Args:
            data: The BCS-encoded bytes to deserialize from.
        """
        self._length = len(data)
        self._input = io.BytesIO(data)

    def remaining(self) -> int:
        """Get the number of bytes remaining in the input stream.

        Returns:
            The number of unread bytes remaining in the stream.
        """
        return self._length - self._input.tell()

    def bool(self) -> bool:
        """Read a boolean value from the stream.

        BCS encodes booleans as a single byte: 0 for False, 1 for True.

        Returns:
            The deserialized boolean value.

        Raises:
            Exception: If the byte value is not 0 or 1, or if there's
                insufficient data in the stream.
        """
        value = int.from_bytes(self._read(1), byteorder="little", signed=False)
        if value == 0:
            return False
        elif value == 1:
            return True
        else:
            raise Exception("Unexpected boolean value: ", value)

    def to_bytes(self) -> bytes:
        """Read a byte array from the stream.

        BCS encodes byte arrays as a ULEB128 length followed by the raw bytes.

        Returns:
            The deserialized byte array.

        Raises:
            Exception: If there's insufficient data in the stream or if the
                length encoding is invalid.
        """
        return self._read(self.uleb128())

    def fixed_bytes(self, length: int) -> bytes:
        """Read a fixed-length byte array from the stream.

        Args:
            length: The exact number of bytes to read.

        Returns:
            The deserialized byte array of the specified length.

        Raises:
            Exception: If there are insufficient bytes remaining in the stream.
        """
        return self._read(length)

    def map(
        self,
        key_decoder: typing.Callable[[Deserializer], typing.Any],
        value_decoder: typing.Callable[[Deserializer], typing.Any],
    ) -> Dict[typing.Any, typing.Any]:
        """Read a map (dictionary) from the stream.

        BCS encodes maps as a ULEB128 length followed by key-value pairs.
        The pairs are sorted by the BCS encoding of the keys.

        Args:
            key_decoder: Function to decode each key from the stream.
            value_decoder: Function to decode each value from the stream.

        Returns:
            A dictionary containing the deserialized key-value pairs.

        Raises:
            Exception: If there's insufficient data or if the decoders fail.

        Examples:
            Reading a map of string keys to u32 values::

                mapping = der.map(Deserializer.str, Deserializer.u32)
        """
        length = self.uleb128()
        values: Dict = {}
        while len(values) < length:
            key = key_decoder(self)
            value = value_decoder(self)
            values[key] = value
        return values

    def sequence(
        self,
        value_decoder: typing.Callable[[Deserializer], typing.Any],
    ) -> List[typing.Any]:
        """Read a sequence (list) from the stream.

        BCS encodes sequences as a ULEB128 length followed by the elements.

        Args:
            value_decoder: Function to decode each element from the stream.

        Returns:
            A list containing the deserialized elements.

        Raises:
            Exception: If there's insufficient data or if the decoder fails.

        Examples:
            Reading a sequence of strings::

                strings = der.sequence(Deserializer.str)

            Reading a sequence of u32 values::

                numbers = der.sequence(Deserializer.u32)
        """
        length = self.uleb128()
        values: List = []
        while len(values) < length:
            values.append(value_decoder(self))
        return values

    def str(self) -> str:
        """Read a UTF-8 string from the stream.

        BCS encodes strings as byte arrays (ULEB128 length + bytes) that
        contain valid UTF-8 data.

        Returns:
            The deserialized string.

        Raises:
            Exception: If there's insufficient data in the stream.
            UnicodeDecodeError: If the bytes don't form valid UTF-8.
        """
        return self.to_bytes().decode()

    def struct(self, struct: typing.Any) -> typing.Any:
        """Deserialize a custom struct from the stream.

        This method delegates to the struct's `deserialize` method to handle
        custom deserialization logic.

        Args:
            struct: A class or type that implements the `deserialize` method.

        Returns:
            The deserialized struct instance.

        Raises:
            Exception: If the struct doesn't have a deserialize method or
                if deserialization fails.
        """
        return struct.deserialize(self)

    def u8(self) -> int:
        """Read an 8-bit unsigned integer from the stream.

        Returns:
            The deserialized u8 value (0-255).

        Raises:
            Exception: If there's insufficient data in the stream.
        """
        return self._read_int(1)

    def u16(self) -> int:
        """Read a 16-bit unsigned integer from the stream.

        Returns:
            The deserialized u16 value (0-65535).

        Raises:
            Exception: If there's insufficient data in the stream.
        """
        return self._read_int(2)

    def u32(self) -> int:
        """Read a 32-bit unsigned integer from the stream.

        Returns:
            The deserialized u32 value (0-4294967295).

        Raises:
            Exception: If there's insufficient data in the stream.
        """
        return self._read_int(4)

    def u64(self) -> int:
        """Read a 64-bit unsigned integer from the stream.

        Returns:
            The deserialized u64 value (0-18446744073709551615).

        Raises:
            Exception: If there's insufficient data in the stream.
        """
        return self._read_int(8)

    def u128(self) -> int:
        """Read a 128-bit unsigned integer from the stream.

        Returns:
            The deserialized u128 value (0-340282366920938463463374607431768211455).

        Raises:
            Exception: If there's insufficient data in the stream.
        """
        return self._read_int(16)

    def u256(self) -> int:
        """Read a 256-bit unsigned integer from the stream.

        Returns:
            The deserialized u256 value.

        Raises:
            Exception: If there's insufficient data in the stream.
        """
        return self._read_int(32)

    def uleb128(self) -> int:
        """Read a ULEB128 (unsigned little-endian base 128) encoded integer.

        ULEB128 is a variable-length encoding where each byte contains 7 bits
        of data and a continuation bit. It's commonly used for encoding lengths
        and small integers efficiently.

        Returns:
            The decoded integer value (0-4294967295).

        Raises:
            Exception: If the encoded value exceeds u32 range or if there's
                insufficient data in the stream.
        """
        value = 0
        shift = 0

        while value <= MAX_U32:
            byte = self._read_int(1)
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                break
            shift += 7

        if value > MAX_U32:
            raise Exception("Unexpectedly large uleb128 value")

        return value

    def _read(self, length: int) -> bytes:
        """Read a specified number of bytes from the input stream.

        Args:
            length: Number of bytes to read.

        Returns:
            The requested bytes.

        Raises:
            Exception: If there are insufficient bytes remaining in the stream.
        """
        value = self._input.read(length)
        if value is None or len(value) < length:
            actual_length = 0 if value is None else len(value)
            error = (
                f"Unexpected end of input. Requested: {length}, found: {actual_length}"
            )
            raise Exception(error)
        return value

    def _read_int(self, length: int) -> int:
        """Read an integer of specified byte length from the stream.

        Args:
            length: Number of bytes representing the integer.

        Returns:
            The integer value interpreted as little-endian unsigned.

        Raises:
            Exception: If there are insufficient bytes in the stream.
        """
        return int.from_bytes(self._read(length), byteorder="little", signed=False)


class Serializer:
    """A BCS serializer for writing data to a byte stream.

    The Serializer class provides methods to write various data types to a
    BCS-encoded byte stream. It maintains an internal output buffer and provides
    methods to serialize primitive types, collections, and custom structures.

    Attributes:
        _output: Internal BytesIO buffer for accumulating serialized data.

    Examples:
        Basic usage::

            ser = Serializer()
            ser.bool(True)
            ser.str("hello")
            data = ser.output()  # Get the serialized bytes

        Serializing collections::

            # Serialize a sequence of strings
            ser.sequence(["a", "b", "c"], Serializer.str)

            # Serialize a map
            ser.map({"key": 42}, Serializer.str, Serializer.u32)
    """

    _output: io.BytesIO

    def __init__(self):
        """Initialize a new serializer with an empty output buffer."""
        self._output = io.BytesIO()

    def output(self) -> bytes:
        """Get the accumulated serialized data as bytes.

        Returns:
            The BCS-encoded bytes written to this serializer.
        """
        return self._output.getvalue()

    def bool(self, value: bool):
        """Write a boolean value to the stream.

        BCS encodes booleans as a single byte: 0 for False, 1 for True.

        Args:
            value: The boolean value to serialize.
        """
        self._write_int(int(value), 1)

    def to_bytes(self, value: bytes):
        """Write a byte array to the stream.

        BCS encodes byte arrays as a ULEB128 length followed by the raw bytes.

        Args:
            value: The byte array to serialize.
        """
        self.uleb128(len(value))
        self._output.write(value)

    def fixed_bytes(self, value):
        """Write a fixed-length byte array to the stream.

        This method writes raw bytes without any length prefix.

        Args:
            value: The byte array to write directly to the stream.
        """
        self._output.write(value)

    def map(
        self,
        values: typing.Dict[typing.Any, typing.Any],
        key_encoder: typing.Callable[[Serializer, typing.Any], None],
        value_encoder: typing.Callable[[Serializer, typing.Any], None],
    ):
        """Write a map (dictionary) to the stream.

        BCS encodes maps as a ULEB128 length followed by key-value pairs.
        The pairs are sorted by the BCS encoding of the keys to ensure
        canonical ordering.

        Args:
            values: The dictionary to serialize.
            key_encoder: Function to encode each key.
            value_encoder: Function to encode each value.

        Examples:
            Serializing a map of string keys to u32 values::

                mapping = {"a": 1, "b": 2}
                ser.map(mapping, Serializer.str, Serializer.u32)
        """
        encoded_values = []
        for key, value in values.items():
            encoded_values.append(
                (encoder(key, key_encoder), encoder(value, value_encoder))
            )
        encoded_values.sort(key=lambda item: item[0])

        self.uleb128(len(encoded_values))
        for key, value in encoded_values:
            self.fixed_bytes(key)
            self.fixed_bytes(value)

    @staticmethod
    def sequence_serializer(
        value_encoder: typing.Callable[[Serializer, typing.Any], None],
    ):
        """Create a reusable sequence serializer function.

        This is a helper method that returns a function that can be used
        to serialize sequences with a specific encoder.

        Args:
            value_encoder: Function to encode each element in sequences.

        Returns:
            A function that takes a serializer and a list of values and
            serializes the sequence.

        Examples:
            Creating a string sequence serializer::

                str_seq = Serializer.sequence_serializer(Serializer.str)
                str_seq(ser, ["a", "b", "c"])
        """
        return lambda self, values: self.sequence(values, value_encoder)

    def sequence(
        self,
        values: typing.List[typing.Any],
        value_encoder: typing.Callable[[Serializer, typing.Any], None],
    ):
        """Write a sequence (list) to the stream.

        BCS encodes sequences as a ULEB128 length followed by the elements.

        Args:
            values: The list of values to serialize.
            value_encoder: Function to encode each element.

        Examples:
            Serializing a sequence of strings::

                ser.sequence(["a", "b", "c"], Serializer.str)

            Serializing a sequence of u32 values::

                ser.sequence([1, 2, 3], Serializer.u32)
        """
        self.uleb128(len(values))
        for value in values:
            self.fixed_bytes(encoder(value, value_encoder))

    def str(self, value: str):
        """Write a UTF-8 string to the stream.

        BCS encodes strings as byte arrays (ULEB128 length + bytes) containing
        valid UTF-8 data.

        Args:
            value: The string to serialize.

        Raises:
            UnicodeEncodeError: If the string cannot be encoded as UTF-8.
        """
        self.to_bytes(value.encode())

    def struct(self, value: typing.Any):
        """Serialize a custom struct to the stream.

        This method delegates to the struct's `serialize` method to handle
        custom serialization logic.

        Args:
            value: An object that implements the `serialize` method.

        Raises:
            AttributeError: If the value doesn't have a serialize method.
            Exception: If serialization fails.
        """
        value.serialize(self)

    def u8(self, value: int):
        """Write an 8-bit unsigned integer to the stream.

        Args:
            value: The u8 value to serialize (0-255).

        Raises:
            Exception: If the value is outside the valid range.
        """
        if value > MAX_U8:
            raise Exception(f"Cannot encode {value} into u8")

        self._write_int(value, 1)

    def u16(self, value: int):
        """Write a 16-bit unsigned integer to the stream.

        Args:
            value: The u16 value to serialize (0-65535).

        Raises:
            Exception: If the value is outside the valid range.
        """
        if value > MAX_U16:
            raise Exception(f"Cannot encode {value} into u16")

        self._write_int(value, 2)

    def u32(self, value: int):
        """Write a 32-bit unsigned integer to the stream.

        Args:
            value: The u32 value to serialize (0-4294967295).

        Raises:
            Exception: If the value is outside the valid range.
        """
        if value > MAX_U32:
            raise Exception(f"Cannot encode {value} into u32")

        self._write_int(value, 4)

    def u64(self, value: int):
        """Write a 64-bit unsigned integer to the stream.

        Args:
            value: The u64 value to serialize (0-18446744073709551615).

        Raises:
            Exception: If the value is outside the valid range.
        """
        if value > MAX_U64:
            raise Exception(f"Cannot encode {value} into u64")

        self._write_int(value, 8)

    def u128(self, value: int):
        """Write a 128-bit unsigned integer to the stream.

        Args:
            value: The u128 value to serialize (0-340282366920938463463374607431768211455).

        Raises:
            Exception: If the value is outside the valid range.
        """
        if value > MAX_U128:
            raise Exception(f"Cannot encode {value} into u128")

        self._write_int(value, 16)

    def u256(self, value: int):
        """Write a 256-bit unsigned integer to the stream.

        Args:
            value: The u256 value to serialize.

        Raises:
            Exception: If the value is outside the valid range.
        """
        if value > MAX_U256:
            raise Exception(f"Cannot encode {value} into u256")

        self._write_int(value, 32)

    def uleb128(self, value: int):
        """Write a ULEB128 (unsigned little-endian base 128) encoded integer.

        ULEB128 is a variable-length encoding where each byte contains 7 bits
        of data and a continuation bit. It's commonly used for encoding lengths
        and small integers efficiently.

        Args:
            value: The integer value to encode (0-4294967295).

        Raises:
            Exception: If the value exceeds the u32 range.
        """
        if value > MAX_U32:
            raise Exception(f"Cannot encode {value} into uleb128")

        while value >= 0x80:
            # Write 7 (lowest) bits of data and set the 8th bit to 1.
            byte = value & 0x7F
            self.u8(byte | 0x80)
            value >>= 7

        # Write the remaining bits of data and set the highest bit to 0.
        self.u8(value & 0x7F)

    def _write_int(self, value: int, length: int):
        """Write an integer of specified byte length to the stream.

        Args:
            value: The integer value to write.
            length: Number of bytes to use for the integer representation.
        """
        self._output.write(value.to_bytes(length, "little", signed=False))


def encoder(
    value: typing.Any, encoder: typing.Callable[[Serializer, typing.Any], typing.Any]
) -> bytes:
    """Encode a single value using the specified encoder function.

    This is a convenience function that creates a new Serializer, uses the
    provided encoder function to serialize the value, and returns the bytes.

    Args:
        value: The value to encode.
        encoder: Function that takes a serializer and value and encodes the value.

    Returns:
        The BCS-encoded bytes for the value.

    Examples:
        Encoding a string::

            data = encoder("hello", Serializer.str)

        Encoding an integer::

            data = encoder(42, Serializer.u32)
    """
    ser = Serializer()
    encoder(ser, value)
    return ser.output()


class Test(unittest.TestCase):
    """Test suite for BCS serialization and deserialization.

    This test class contains comprehensive tests for all BCS data types and
    operations to ensure correct serialization and deserialization behavior.
    Each test follows the pattern of serializing a value, deserializing it,
    and verifying the round-trip preserves the original value.
    """

    def test_bool_true(self):
        in_value = True

        ser = Serializer()
        ser.bool(in_value)
        der = Deserializer(ser.output())
        out_value = der.bool()

        self.assertEqual(in_value, out_value)

    def test_bool_false(self):
        in_value = False

        ser = Serializer()
        ser.bool(in_value)
        der = Deserializer(ser.output())
        out_value = der.bool()

        self.assertEqual(in_value, out_value)

    def test_bool_error(self):
        ser = Serializer()
        ser.u8(32)
        der = Deserializer(ser.output())
        with self.assertRaises(Exception):
            der.bool()

    def test_bytes(self):
        in_value = b"1234567890"

        ser = Serializer()
        ser.to_bytes(in_value)
        der = Deserializer(ser.output())
        out_value = der.to_bytes()

        self.assertEqual(in_value, out_value)

    def test_map(self):
        in_value = {"a": 12345, "b": 99234, "c": 23829}

        ser = Serializer()
        ser.map(in_value, Serializer.str, Serializer.u32)
        der = Deserializer(ser.output())
        out_value = der.map(Deserializer.str, Deserializer.u32)

        self.assertEqual(in_value, out_value)

    def test_sequence(self):
        in_value = ["a", "abc", "def", "ghi"]

        ser = Serializer()
        ser.sequence(in_value, Serializer.str)
        der = Deserializer(ser.output())
        out_value = der.sequence(Deserializer.str)

        self.assertEqual(in_value, out_value)

    def test_sequence_serializer(self):
        in_value = ["a", "abc", "def", "ghi"]

        ser = Serializer()
        seq_ser = Serializer.sequence_serializer(Serializer.str)
        seq_ser(ser, in_value)
        der = Deserializer(ser.output())
        out_value = der.sequence(Deserializer.str)

        self.assertEqual(in_value, out_value)

    def test_str(self):
        in_value = "1234567890"

        ser = Serializer()
        ser.str(in_value)
        der = Deserializer(ser.output())
        out_value = der.str()

        self.assertEqual(in_value, out_value)

    def test_u8(self):
        in_value = 15

        ser = Serializer()
        ser.u8(in_value)
        der = Deserializer(ser.output())
        out_value = der.u8()

        self.assertEqual(in_value, out_value)

    def test_u16(self):
        in_value = 11115

        ser = Serializer()
        ser.u16(in_value)
        der = Deserializer(ser.output())
        out_value = der.u16()

        self.assertEqual(in_value, out_value)

    def test_u32(self):
        in_value = 1111111115

        ser = Serializer()
        ser.u32(in_value)
        der = Deserializer(ser.output())
        out_value = der.u32()

        self.assertEqual(in_value, out_value)

    def test_u64(self):
        in_value = 1111111111111111115

        ser = Serializer()
        ser.u64(in_value)
        der = Deserializer(ser.output())
        out_value = der.u64()

        self.assertEqual(in_value, out_value)

    def test_u128(self):
        in_value = 1111111111111111111111111111111111115

        ser = Serializer()
        ser.u128(in_value)
        der = Deserializer(ser.output())
        out_value = der.u128()

        self.assertEqual(in_value, out_value)

    def test_u256(self):
        in_value = 111111111111111111111111111111111111111111111111111111111111111111111111111115

        ser = Serializer()
        ser.u256(in_value)
        der = Deserializer(ser.output())
        out_value = der.u256()

        self.assertEqual(in_value, out_value)

    def test_uleb128(self):
        in_value = 1111111115

        ser = Serializer()
        ser.uleb128(in_value)
        der = Deserializer(ser.output())
        out_value = der.uleb128()

        self.assertEqual(in_value, out_value)


if __name__ == "__main__":
    unittest.main()
