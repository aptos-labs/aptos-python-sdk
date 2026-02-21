# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
BCS (Binary Canonical Serialization) for the Aptos Python SDK.

Implements the BCS specification used throughout the Aptos blockchain for
deterministic binary encoding of structured data.  See:
https://github.com/diem/bcs

Usage
-----
Serializing a value::

    ser = Serializer()
    ser.u64(42)
    ser.str("hello")
    raw: bytes = ser.output()

Deserializing a value::

    der = Deserializer(raw)
    value: int  = der.u64()
    text: str   = der.str()

Implementing the Serializable protocol::

    class MyType:
        def serialize(self, serializer: Serializer) -> None:
            serializer.u64(self.amount)
            serializer.str(self.label)

        def to_bytes(self) -> bytes:          # provided by default mixin
            ser = Serializer()
            ser.struct(self)
            return ser.output()

        @staticmethod
        def deserialize(deserializer: Deserializer) -> "MyType": ...

        @classmethod
        def from_bytes(cls, data: bytes) -> "MyType":   # provided by default mixin
            der = Deserializer(data)
            return der.struct(cls)
"""

import io
from typing import Any, Callable

from typing_extensions import Protocol, runtime_checkable

from .errors import BcsError

# ---------------------------------------------------------------------------
# Integer range constants
# ---------------------------------------------------------------------------

MAX_U8: int = 2**8 - 1
MAX_U16: int = 2**16 - 1
MAX_U32: int = 2**32 - 1
MAX_U64: int = 2**64 - 1
MAX_U128: int = 2**128 - 1
MAX_U256: int = 2**256 - 1

# ULEB128 encodes lengths and variant indices; the BCS spec caps them at u32.
_MAX_ULEB128: int = MAX_U32

# Safety cap on ULEB128 decode iterations (5 bytes covers u32 max).
_ULEB128_MAX_BYTES: int = 5


# ---------------------------------------------------------------------------
# Serializable protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Serializable(Protocol):
    """
    Protocol for types that can be BCS-serialized.

    Implementors must provide ``serialize``.  The ``to_bytes`` helper
    is provided as a default convenience implementation.
    """

    def serialize(self, serializer: "Serializer") -> None:
        """Write this value into *serializer*."""
        ...

    def to_bytes(self) -> bytes:
        """Serialize ``self`` to a BCS byte string."""
        ser = Serializer()
        ser.struct(self)
        return ser.output()


# ---------------------------------------------------------------------------
# Deserializable protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Deserializable(Protocol):
    """
    Protocol for types that can be BCS-deserialized.

    Implementors must provide the ``deserialize`` static method.
    The ``from_bytes`` class method is provided as a default convenience
    implementation.
    """

    @staticmethod
    def deserialize(deserializer: "Deserializer") -> "Deserializable":
        """Read and return an instance from *deserializer*."""
        ...

    @classmethod
    def from_bytes(cls, data: bytes) -> "Deserializable":
        """Deserialize an instance from a complete BCS byte string."""
        der = Deserializer(data)
        return der.struct(cls)


# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------


class Serializer:
    """
    Write BCS-encoded values into an internal buffer.

    All numeric types are written in little-endian byte order.
    Lengths and sequence counts are encoded as ULEB128.
    """

    _output: io.BytesIO

    def __init__(self) -> None:
        self._output = io.BytesIO()

    # ------------------------------------------------------------------
    # Buffer access
    # ------------------------------------------------------------------

    def output(self) -> bytes:
        """Return the serialized bytes accumulated so far."""
        return self._output.getvalue()

    # ------------------------------------------------------------------
    # Primitive types
    # ------------------------------------------------------------------

    def bool(self, value: bool) -> None:
        """Serialize a boolean as a single byte: 0x00 (False) or 0x01 (True)."""
        self._write_int(int(value), 1)

    def u8(self, value: int) -> None:
        """Serialize an unsigned 8-bit integer (1 byte, little-endian)."""
        if value < 0 or value > MAX_U8:
            raise BcsError(
                f"Cannot encode {value} into u8: value must be in [0, {MAX_U8}]"
            )
        self._write_int(value, 1)

    def u16(self, value: int) -> None:
        """Serialize an unsigned 16-bit integer (2 bytes, little-endian)."""
        if value < 0 or value > MAX_U16:
            raise BcsError(
                f"Cannot encode {value} into u16: value must be in [0, {MAX_U16}]"
            )
        self._write_int(value, 2)

    def u32(self, value: int) -> None:
        """Serialize an unsigned 32-bit integer (4 bytes, little-endian)."""
        if value < 0 or value > MAX_U32:
            raise BcsError(
                f"Cannot encode {value} into u32: value must be in [0, {MAX_U32}]"
            )
        self._write_int(value, 4)

    def u64(self, value: int) -> None:
        """Serialize an unsigned 64-bit integer (8 bytes, little-endian)."""
        if value < 0 or value > MAX_U64:
            raise BcsError(
                f"Cannot encode {value} into u64: value must be in [0, {MAX_U64}]"
            )
        self._write_int(value, 8)

    def u128(self, value: int) -> None:
        """Serialize an unsigned 128-bit integer (16 bytes, little-endian)."""
        if value < 0 or value > MAX_U128:
            raise BcsError(
                f"Cannot encode {value} into u128: value must be in [0, {MAX_U128}]"
            )
        self._write_int(value, 16)

    def u256(self, value: int) -> None:
        """Serialize an unsigned 256-bit integer (32 bytes, little-endian)."""
        if value < 0 or value > MAX_U256:
            raise BcsError(
                f"Cannot encode {value} into u256: value must be in [0, {MAX_U256}]"
            )
        self._write_int(value, 32)

    # ------------------------------------------------------------------
    # Byte strings
    # ------------------------------------------------------------------

    def to_bytes(self, value: bytes) -> None:
        """Serialize a byte string with a ULEB128 length prefix."""
        self.uleb128(len(value))
        self._output.write(value)

    def fixed_bytes(self, value: bytes) -> None:
        """Write raw bytes with no length prefix."""
        self._output.write(value)

    # ------------------------------------------------------------------
    # String
    # ------------------------------------------------------------------

    def str(self, value: str) -> None:
        """Serialize a UTF-8 string with a ULEB128 length prefix (in bytes)."""
        try:
            encoded = value.encode("utf-8")
        except (UnicodeEncodeError, AttributeError) as exc:
            raise BcsError(f"Cannot UTF-8 encode string: {exc}") from exc
        self.to_bytes(encoded)

    # ------------------------------------------------------------------
    # Structured types
    # ------------------------------------------------------------------

    def struct(self, value: Any) -> None:
        """Serialize a Serializable object by calling its ``serialize`` method."""
        value.serialize(self)

    def sequence(
        self,
        values: list[Any],
        value_encoder: Callable[["Serializer", Any], None],
    ) -> None:
        """
        Serialize a homogeneous sequence.

        Writes a ULEB128 element count followed by each element encoded
        using *value_encoder*.
        """
        self.uleb128(len(values))
        for item in values:
            self.fixed_bytes(encoder(item, value_encoder))

    @staticmethod
    def sequence_serializer(
        value_encoder: Callable[["Serializer", Any], None],
    ) -> Callable[["Serializer", list[Any]], None]:
        """
        Return a callable that serializes a sequence using *value_encoder*.

        This is a convenience factory for embedding sequence serialization
        in contexts that expect a single ``(Serializer, value)`` callable::

            ser_fn = Serializer.sequence_serializer(Serializer.u64)
            ser_fn(serializer, [1, 2, 3])
        """
        return lambda self, values: self.sequence(values, value_encoder)

    def map(
        self,
        values: dict[Any, Any],
        key_encoder: Callable[["Serializer", Any], None],
        value_encoder: Callable[["Serializer", Any], None],
    ) -> None:
        """
        Serialize a mapping in canonical (sorted) order.

        BCS requires map entries to be sorted lexicographically by their
        encoded key bytes to ensure deterministic output.  Writes a
        ULEB128 entry count followed by sorted ``(key_bytes, value_bytes)``
        pairs.
        """
        encoded_pairs: list[tuple[bytes, bytes]] = []
        for key, value in values.items():
            encoded_pairs.append(
                (
                    encoder(key, key_encoder),
                    encoder(value, value_encoder),
                )
            )
        encoded_pairs.sort(key=lambda pair: pair[0])

        self.uleb128(len(encoded_pairs))
        for key_bytes, value_bytes in encoded_pairs:
            self.fixed_bytes(key_bytes)
            self.fixed_bytes(value_bytes)

    def option(
        self,
        value: Any | None,
        value_encoder: Callable[["Serializer", Any], None],
    ) -> None:
        """
        Serialize an ``Option<T>`` value.

        Writes ``0x00`` for ``None`` (the ``None`` variant), or ``0x01``
        followed by the encoded value for ``Some(value)``.
        """
        if value is None:
            self._write_int(0, 1)
        else:
            self._write_int(1, 1)
            value_encoder(self, value)

    def variant_index(self, idx: int) -> None:
        """
        Serialize an enum variant discriminant as a ULEB128 value.

        Used when serializing tagged union / enum types so the deserializer
        knows which variant follows.
        """
        if idx < 0 or idx > _MAX_ULEB128:
            raise BcsError(
                f"Cannot encode {idx} as variant index: "
                f"value must be in [0, {_MAX_ULEB128}]"
            )
        self.uleb128(idx)

    # ------------------------------------------------------------------
    # ULEB128
    # ------------------------------------------------------------------

    def uleb128(self, value: int) -> None:
        """
        Serialize a non-negative integer using ULEB128 variable-length encoding.

        The BCS specification limits ULEB128 values to u32 range
        (``[0, 2^32 - 1]``).  Each 7-bit group is emitted as one byte,
        with the high bit set on all bytes except the last.
        """
        if value < 0 or value > _MAX_ULEB128:
            raise BcsError(
                f"Cannot encode {value} into uleb128: "
                f"value must be in [0, {_MAX_ULEB128}]"
            )
        while value >= 0x80:
            # Emit the low 7 bits with the continuation bit set.
            byte = (value & 0x7F) | 0x80
            self._output.write(bytes([byte]))
            value >>= 7
        # Emit the remaining bits with the continuation bit clear.
        self._output.write(bytes([value & 0x7F]))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_int(self, value: int, length: int) -> None:
        self._output.write(value.to_bytes(length, byteorder="little", signed=False))


# ---------------------------------------------------------------------------
# Deserializer
# ---------------------------------------------------------------------------


class Deserializer:
    """
    Read BCS-encoded values from a byte buffer.

    All numeric types are read in little-endian byte order.
    Lengths and sequence counts are decoded from ULEB128.
    """

    _input: io.BytesIO
    _length: int

    def __init__(self, data: bytes) -> None:
        self._length = len(data)
        self._input = io.BytesIO(data)

    # ------------------------------------------------------------------
    # Buffer state
    # ------------------------------------------------------------------

    def remaining(self) -> int:
        """Return the number of bytes not yet consumed."""
        return self._length - self._input.tell()

    # ------------------------------------------------------------------
    # Primitive types
    # ------------------------------------------------------------------

    def bool(self) -> bool:
        """Deserialize a single-byte boolean (0x00 → False, 0x01 → True)."""
        raw = self._read_int(1)
        if raw == 0:
            return False
        if raw == 1:
            return True
        raise BcsError(
            f"Invalid boolean encoding: expected 0x00 or 0x01, got 0x{raw:02x}"
        )

    def u8(self) -> int:
        """Deserialize an unsigned 8-bit integer."""
        return self._read_int(1)

    def u16(self) -> int:
        """Deserialize an unsigned 16-bit integer (little-endian)."""
        return self._read_int(2)

    def u32(self) -> int:
        """Deserialize an unsigned 32-bit integer (little-endian)."""
        return self._read_int(4)

    def u64(self) -> int:
        """Deserialize an unsigned 64-bit integer (little-endian)."""
        return self._read_int(8)

    def u128(self) -> int:
        """Deserialize an unsigned 128-bit integer (little-endian)."""
        return self._read_int(16)

    def u256(self) -> int:
        """Deserialize an unsigned 256-bit integer (little-endian)."""
        return self._read_int(32)

    # ------------------------------------------------------------------
    # Byte strings
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Deserialize a length-prefixed byte string (ULEB128 length)."""
        length = self.uleb128()
        return self._read(length)

    def fixed_bytes(self, length: int) -> bytes:
        """Deserialize exactly *length* raw bytes with no length prefix."""
        return self._read(length)

    # ------------------------------------------------------------------
    # String
    # ------------------------------------------------------------------

    def str(self) -> str:
        """Deserialize a UTF-8 string (ULEB128 byte-length prefix)."""
        raw = self.to_bytes()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BcsError(f"Invalid UTF-8 string encoding: {exc}") from exc

    # ------------------------------------------------------------------
    # Structured types
    # ------------------------------------------------------------------

    def struct(self, cls: Any) -> Any:
        """
        Deserialize a structured type by calling ``cls.deserialize(self)``.

        *cls* must implement the ``Deserializable`` protocol, i.e. it must
        expose a ``deserialize(deserializer)`` static/class method.
        """
        return cls.deserialize(self)

    def sequence(
        self,
        value_decoder: Callable[["Deserializer"], Any],
    ) -> list[Any]:
        """
        Deserialize a homogeneous sequence.

        Reads a ULEB128 element count and then decodes each element
        using *value_decoder*.
        """
        length = self.uleb128()
        values: list[Any] = []
        while len(values) < length:
            values.append(value_decoder(self))
        return values

    def map(
        self,
        key_decoder: Callable[["Deserializer"], Any],
        value_decoder: Callable[["Deserializer"], Any],
    ) -> dict[Any, Any]:
        """
        Deserialize a mapping.

        Reads a ULEB128 entry count and then decodes each ``(key, value)``
        pair using the provided decoders.
        """
        length = self.uleb128()
        result: dict[Any, Any] = {}
        while len(result) < length:
            key = key_decoder(self)
            value = value_decoder(self)
            result[key] = value
        return result

    def option(
        self,
        value_decoder: Callable[["Deserializer"], Any],
    ) -> Any | None:
        """
        Deserialize an ``Option<T>`` value.

        Reads a tag byte: ``0x00`` means ``None``; ``0x01`` means ``Some``
        and the actual value is read next using *value_decoder*.
        """
        tag = self._read_int(1)
        if tag == 0:
            return None
        if tag == 1:
            return value_decoder(self)
        raise BcsError(f"Invalid option tag: expected 0x00 or 0x01, got 0x{tag:02x}")

    def variant_index(self) -> int:
        """
        Deserialize an enum variant discriminant (ULEB128-encoded).

        Returns the integer index of the enum variant to be decoded next.
        """
        return self.uleb128()

    # ------------------------------------------------------------------
    # ULEB128
    # ------------------------------------------------------------------

    def uleb128(self) -> int:
        """
        Deserialize a ULEB128-encoded unsigned integer.

        Reads up to ``_ULEB128_MAX_BYTES`` bytes.  Raises ``BcsError``
        if the encoded value exceeds u32 range or if the stream is
        unexpectedly exhausted.
        """
        value = 0
        shift = 0

        for _ in range(_ULEB128_MAX_BYTES):
            byte = self._read_int(1)
            value |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        else:
            # Loop exhausted without finding a terminal byte.
            raise BcsError(
                f"ULEB128 value exceeds maximum of {_ULEB128_MAX_BYTES} bytes"
            )

        if value > _MAX_ULEB128:
            raise BcsError(
                f"ULEB128 decoded value {value} exceeds maximum u32 value "
                f"{_MAX_ULEB128}"
            )

        return value

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read(self, length: int) -> bytes:
        """Read exactly *length* bytes from the buffer."""
        data = self._input.read(length)
        if data is None or len(data) < length:
            actual = 0 if data is None else len(data)
            raise BcsError(
                f"Unexpected end of input: requested {length} bytes, "
                f"only {actual} available"
            )
        return data

    def _read_int(self, length: int) -> int:
        return int.from_bytes(self._read(length), byteorder="little", signed=False)


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------


def encoder(
    value: Any,
    encode_fn: Callable[[Serializer, Any], None],
) -> bytes:
    """
    Serialize *value* to bytes using *encode_fn* and return the result.

    This is a convenience helper for contexts that need the encoded bytes
    of a single value without managing a ``Serializer`` manually::

        raw = encoder(42, Serializer.u64)
        raw = encoder(my_struct, Serializer.struct)

    It is also used internally by :meth:`Serializer.sequence` and
    :meth:`Serializer.map` to encode individual elements.
    """
    ser = Serializer()
    encode_fn(ser, value)
    return ser.output()
