"""Chain ID — identifies which Aptos network a transaction targets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from ..bcs import Deserializer, Serializer


@dataclass(frozen=True, slots=True)
class ChainId:
    """Single-byte chain identifier."""

    value: int

    MAINNET: ClassVar[ChainId]
    TESTNET: ClassVar[ChainId]

    def __post_init__(self) -> None:
        if not (0 <= self.value <= 255):
            raise ValueError(f"Chain ID must be 0-255, got {self.value}")

    @staticmethod
    def deserialize(deserializer: Deserializer) -> ChainId:
        return ChainId(deserializer.u8())

    def serialize(self, serializer: Serializer) -> None:
        serializer.u8(self.value)


# Initialize class-level constants after class definition
setattr(ChainId, "MAINNET", ChainId(1))
setattr(ChainId, "TESTNET", ChainId(2))
