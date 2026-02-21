# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
ChainId — an 8-bit unsigned integer that identifies an Aptos network.

Spec reference: Aptos SDK Specification v1.0.0, section 01 (Core Types).

Well-known chain IDs:
  1   — mainnet
  2   — testnet
  4   — localnet (local development node)
"""

from .bcs import Deserializer, Serializer

_MIN_VALUE: int = 0
_MAX_VALUE: int = 255  # u8 range


class ChainId:
    """
    An unsigned 8-bit integer identifying an Aptos chain.

    :param value: An integer in the range [0, 255].
    :raises ValueError: If *value* is outside the valid u8 range.
    """

    __slots__ = ("_value",)

    def __init__(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError(
                f"ChainId value must be an int, got {type(value).__name__!r}."
            )
        if value < _MIN_VALUE or value > _MAX_VALUE:
            raise ValueError(
                f"ChainId value {value!r} is out of range; "
                f"must be between {_MIN_VALUE} and {_MAX_VALUE} inclusive (u8)."
            )
        object.__setattr__(self, "_value", value)

    # ------------------------------------------------------------------
    # Immutability guard
    # ------------------------------------------------------------------

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ChainId is immutable.")

    # ------------------------------------------------------------------
    # Public value property
    # ------------------------------------------------------------------

    @property
    def value(self) -> int:
        """The raw u8 chain ID value."""
        return object.__getattribute__(self, "_value")

    # ------------------------------------------------------------------
    # Equality, hashing, display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ChainId):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return f"ChainId({self.value})"

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Serialize the chain ID as a single unsigned byte (u8)."""
        serializer.u8(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "ChainId":
        """Deserialize a ChainId from a single unsigned byte (u8)."""
        return ChainId(deserializer.u8())
