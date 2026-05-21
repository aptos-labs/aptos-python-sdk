"""BCS Serializer — encodes Python values into Binary Canonical Serialization format."""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import Any

from ..errors import BcsSerializationError

_bool = bool
_str = str

MAX_U8 = 2**8 - 1
MAX_U16 = 2**16 - 1
MAX_U32 = 2**32 - 1
MAX_U64 = 2**64 - 1
MAX_U128 = 2**128 - 1
MAX_U256 = 2**256 - 1

MIN_I8 = -(2**7)
MAX_I8 = 2**7 - 1
MIN_I16 = -(2**15)
MAX_I16 = 2**15 - 1
MIN_I32 = -(2**31)
MAX_I32 = 2**31 - 1
MIN_I64 = -(2**63)
MAX_I64 = 2**63 - 1
MIN_I128 = -(2**127)
MAX_I128 = 2**127 - 1
MIN_I256 = -(2**255)
MAX_I256 = 2**255 - 1


class Serializer:
    __slots__ = ("_output",)

    _output: io.BytesIO

    def __init__(self) -> None:
        self._output = io.BytesIO()

    def output(self) -> bytes:
        return self._output.getvalue()

    # --- Primitive types ---

    def bool(self, value: _bool) -> None:
        self._write_int(int(value), 1)

    def u8(self, value: int) -> None:
        if value < 0 or value > MAX_U8:
            raise BcsSerializationError(f"Cannot encode {value} into u8")
        self._write_int(value, 1)

    def u16(self, value: int) -> None:
        if value < 0 or value > MAX_U16:
            raise BcsSerializationError(f"Cannot encode {value} into u16")
        self._write_int(value, 2)

    def u32(self, value: int) -> None:
        if value < 0 or value > MAX_U32:
            raise BcsSerializationError(f"Cannot encode {value} into u32")
        self._write_int(value, 4)

    def u64(self, value: int) -> None:
        if value < 0 or value > MAX_U64:
            raise BcsSerializationError(f"Cannot encode {value} into u64")
        self._write_int(value, 8)

    def u128(self, value: int) -> None:
        if value < 0 or value > MAX_U128:
            raise BcsSerializationError(f"Cannot encode {value} into u128")
        self._write_int(value, 16)

    def u256(self, value: int) -> None:
        if value < 0 or value > MAX_U256:
            raise BcsSerializationError(f"Cannot encode {value} into u256")
        self._write_int(value, 32)

    # --- Signed integer types ---

    def i8(self, value: int) -> None:
        if value < MIN_I8 or value > MAX_I8:
            raise BcsSerializationError(f"Cannot encode {value} into i8")
        self._write_signed_int(value, 1)

    def i16(self, value: int) -> None:
        if value < MIN_I16 or value > MAX_I16:
            raise BcsSerializationError(f"Cannot encode {value} into i16")
        self._write_signed_int(value, 2)

    def i32(self, value: int) -> None:
        if value < MIN_I32 or value > MAX_I32:
            raise BcsSerializationError(f"Cannot encode {value} into i32")
        self._write_signed_int(value, 4)

    def i64(self, value: int) -> None:
        if value < MIN_I64 or value > MAX_I64:
            raise BcsSerializationError(f"Cannot encode {value} into i64")
        self._write_signed_int(value, 8)

    def i128(self, value: int) -> None:
        if value < MIN_I128 or value > MAX_I128:
            raise BcsSerializationError(f"Cannot encode {value} into i128")
        self._write_signed_int(value, 16)

    def i256(self, value: int) -> None:
        if value < MIN_I256 or value > MAX_I256:
            raise BcsSerializationError(f"Cannot encode {value} into i256")
        self._write_signed_int(value, 32)

    # --- Variable-length encoding ---

    def uleb128(self, value: int) -> None:
        if value < 0 or value > MAX_U32:
            raise BcsSerializationError(f"Cannot encode {value} into uleb128")
        while value >= 0x80:
            byte = value & 0x7F
            self.u8(byte | 0x80)
            value >>= 7
        self.u8(value & 0x7F)

    # --- Bytes and strings ---

    def to_bytes(self, value: bytes) -> None:
        self.uleb128(len(value))
        self._output.write(value)

    def fixed_bytes(self, value: bytes) -> None:
        self._output.write(value)

    def str(self, value: _str) -> None:
        self.to_bytes(value.encode())

    # --- Option ---

    def option(self, value: Any | None, encoder: Callable[[Serializer, Any], None]) -> None:
        if value is None:
            self.bool(False)
        else:
            self.bool(True)
            encoder(self, value)

    # --- Composite types ---

    def struct(self, value: Any) -> None:
        value.serialize(self)

    def sequence(
        self,
        values: list[Any],
        value_encoder: Callable[[Serializer, Any], None],
    ) -> None:
        self.uleb128(len(values))
        for value in values:
            self.fixed_bytes(_encode(value, value_encoder))

    def map(
        self,
        values: dict[Any, Any],
        key_encoder: Callable[[Serializer, Any], None],
        value_encoder: Callable[[Serializer, Any], None],
    ) -> None:
        encoded_values = [
            (_encode(key, key_encoder), _encode(val, value_encoder)) for key, val in values.items()
        ]
        encoded_values.sort(key=lambda item: item[0])
        self.uleb128(len(encoded_values))
        for key, val in encoded_values:
            self.fixed_bytes(key)
            self.fixed_bytes(val)

    @staticmethod
    def sequence_serializer(
        value_encoder: Callable[[Serializer, Any], None],
    ) -> Callable[[Serializer, list[Any]], None]:
        return lambda self, values: self.sequence(values, value_encoder)

    # --- Internal ---

    def _write_int(self, value: int, length: int) -> None:
        self._output.write(value.to_bytes(length, "little", signed=False))

    def _write_signed_int(self, value: int, length: int) -> None:
        self._output.write(value.to_bytes(length, "little", signed=True))


def _encode(value: Any, encoder: Callable[[Serializer, Any], None]) -> bytes:
    ser = Serializer()
    encoder(ser, value)
    return ser.output()
