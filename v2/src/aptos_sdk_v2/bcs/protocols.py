"""BCS serialization/deserialization protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .deserializer import Deserializer
    from .serializer import Serializer


@runtime_checkable
class Serializable(Protocol):
    """Types that can be serialized into BCS bytes."""

    def serialize(self, serializer: Serializer) -> None: ...

    def to_bytes(self) -> bytes:
        from .serializer import Serializer as Ser

        ser = Ser()
        self.serialize(ser)
        return ser.output()


@runtime_checkable
class Deserializable(Protocol):
    """Types that can be deserialized from BCS bytes."""

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Any: ...

    @classmethod
    def from_bytes(cls, data: bytes) -> Any:
        from .deserializer import Deserializer as Des

        return Des(data).struct(cls)
