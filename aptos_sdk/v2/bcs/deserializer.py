"""BCS Deserializer — decodes Binary Canonical Serialization bytes into Python values."""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import Any

from ..errors import BcsDeserializationError

_bool = bool
_str = str

MAX_U32 = 2**32 - 1


class Deserializer:
    __slots__ = ("_input", "_length")

    _input: io.BytesIO
    _length: int

    def __init__(self, data: bytes) -> None:
        self._length = len(data)
        self._input = io.BytesIO(data)

    def remaining(self) -> int:
        return self._length - self._input.tell()

    # --- Primitive types ---

    def bool(self) -> _bool:
        value = int.from_bytes(self._read(1), byteorder="little", signed=False)
        if value == 0:
            return False
        elif value == 1:
            return True
        raise BcsDeserializationError(f"Unexpected boolean value: {value}")

    def u8(self) -> int:
        return self._read_int(1)

    def u16(self) -> int:
        return self._read_int(2)

    def u32(self) -> int:
        return self._read_int(4)

    def u64(self) -> int:
        return self._read_int(8)

    def u128(self) -> int:
        return self._read_int(16)

    def u256(self) -> int:
        return self._read_int(32)

    # --- Variable-length encoding ---

    def uleb128(self) -> int:
        value = 0
        shift = 0
        while value <= MAX_U32:
            byte = self._read_int(1)
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                break
            shift += 7
        if value > MAX_U32:
            raise BcsDeserializationError("Unexpectedly large uleb128 value")
        return value

    # --- Bytes and strings ---

    def to_bytes(self) -> bytes:
        return self._read(self.uleb128())

    def fixed_bytes(self, length: int) -> bytes:
        return self._read(length)

    def str(self) -> _str:
        return self.to_bytes().decode()

    # --- Option ---

    def option(self, decoder: Callable[[Deserializer], Any]) -> Any | None:
        if self.bool():
            return decoder(self)
        return None

    # --- Composite types ---

    def struct(self, struct: Any) -> Any:
        return struct.deserialize(self)

    def sequence(self, value_decoder: Callable[[Deserializer], Any]) -> list[Any]:
        length = self.uleb128()
        return [value_decoder(self) for _ in range(length)]

    def map(
        self,
        key_decoder: Callable[[Deserializer], Any],
        value_decoder: Callable[[Deserializer], Any],
    ) -> dict[Any, Any]:
        length = self.uleb128()
        values: dict[Any, Any] = {}
        for _ in range(length):
            key = key_decoder(self)
            val = value_decoder(self)
            values[key] = val
        return values

    # --- Internal ---

    def _read(self, length: int) -> bytes:
        value = self._input.read(length)
        if value is None or len(value) < length:
            actual = 0 if value is None else len(value)
            raise BcsDeserializationError(
                f"Unexpected end of input. Requested: {length}, found: {actual}"
            )
        return value

    def _read_int(self, length: int) -> int:
        return int.from_bytes(self._read(length), byteorder="little", signed=False)
