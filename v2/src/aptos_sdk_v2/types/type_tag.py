"""Move type system tags — TypeTag, StructTag, and primitive type tags."""

from __future__ import annotations

from dataclasses import dataclass

from ..bcs import Deserializer, Serializer
from ..errors import InvalidTypeTagError
from .account_address import AccountAddress


class TypeTagVariant:
    BOOL = 0
    U8 = 1
    U64 = 2
    U128 = 3
    ACCOUNT_ADDRESS = 4
    SIGNER = 5
    VECTOR = 6
    STRUCT = 7
    U16 = 8
    U32 = 9
    U256 = 10


# --- Primitive tag classes ---


@dataclass(frozen=True, slots=True)
class BoolTag:
    value: bool

    def variant(self) -> int:
        return TypeTagVariant.BOOL

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> BoolTag:
        return BoolTag(deserializer.bool())

    def serialize(self, serializer: Serializer) -> None:
        serializer.bool(self.value)


@dataclass(frozen=True, slots=True)
class U8Tag:
    value: int

    def variant(self) -> int:
        return TypeTagVariant.U8

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U8Tag:
        return U8Tag(deserializer.u8())

    def serialize(self, serializer: Serializer) -> None:
        serializer.u8(self.value)


@dataclass(frozen=True, slots=True)
class U16Tag:
    value: int

    def variant(self) -> int:
        return TypeTagVariant.U16

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U16Tag:
        return U16Tag(deserializer.u16())

    def serialize(self, serializer: Serializer) -> None:
        serializer.u16(self.value)


@dataclass(frozen=True, slots=True)
class U32Tag:
    value: int

    def variant(self) -> int:
        return TypeTagVariant.U32

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U32Tag:
        return U32Tag(deserializer.u32())

    def serialize(self, serializer: Serializer) -> None:
        serializer.u32(self.value)


@dataclass(frozen=True, slots=True)
class U64Tag:
    value: int

    def variant(self) -> int:
        return TypeTagVariant.U64

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U64Tag:
        return U64Tag(deserializer.u64())

    def serialize(self, serializer: Serializer) -> None:
        serializer.u64(self.value)


@dataclass(frozen=True, slots=True)
class U128Tag:
    value: int

    def variant(self) -> int:
        return TypeTagVariant.U128

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U128Tag:
        return U128Tag(deserializer.u128())

    def serialize(self, serializer: Serializer) -> None:
        serializer.u128(self.value)


@dataclass(frozen=True, slots=True)
class U256Tag:
    value: int

    def variant(self) -> int:
        return TypeTagVariant.U256

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U256Tag:
        return U256Tag(deserializer.u256())

    def serialize(self, serializer: Serializer) -> None:
        serializer.u256(self.value)


@dataclass(frozen=True, slots=True)
class AccountAddressTag:
    value: AccountAddress

    def variant(self) -> int:
        return TypeTagVariant.ACCOUNT_ADDRESS

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AccountAddressTag:
        return AccountAddressTag(deserializer.struct(AccountAddress))

    def serialize(self, serializer: Serializer) -> None:
        serializer.struct(self.value)


@dataclass(frozen=True, slots=True)
class SignerTag:
    def variant(self) -> int:
        return TypeTagVariant.SIGNER

    def __str__(self) -> str:
        return "signer"

    @staticmethod
    def deserialize(deserializer: Deserializer) -> SignerTag:
        return SignerTag()

    def serialize(self, serializer: Serializer) -> None:
        pass


# --- StructTag ---


@dataclass(slots=True)
class StructTag:
    address: AccountAddress
    module: str
    name: str
    type_args: list[TypeTag]

    def variant(self) -> int:
        return TypeTagVariant.STRUCT

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, StructTag):
            return NotImplemented
        return (
            self.address == other.address
            and self.module == other.module
            and self.name == other.name
            and self.type_args == other.type_args
        )

    def __str__(self) -> str:
        value = f"{self.address}::{self.module}::{self.name}"
        if self.type_args:
            args = ", ".join(str(a) for a in self.type_args)
            value += f"<{args}>"
        return value

    @staticmethod
    def from_str(type_tag: str) -> StructTag:
        tags, _ = _parse_type_tags(type_tag, 0)
        if not tags:  # pragma: no cover — parser always appends via _make_struct_tag
            raise InvalidTypeTagError(f"Cannot parse type tag: {type_tag}")
        inner = tags[0].value
        if not isinstance(inner, StructTag):  # pragma: no cover — parser only creates StructTags
            raise InvalidTypeTagError(f"Expected StructTag, got {type(inner).__name__}")
        return inner

    @staticmethod
    def deserialize(deserializer: Deserializer) -> StructTag:
        address = deserializer.struct(AccountAddress)
        module = deserializer.str()
        name = deserializer.str()
        type_args = deserializer.sequence(TypeTag.deserialize)
        return StructTag(address, module, name, type_args)

    def serialize(self, serializer: Serializer) -> None:
        self.address.serialize(serializer)
        serializer.str(self.module)
        serializer.str(self.name)
        serializer.sequence(self.type_args, Serializer.struct)


# --- TypeTag (wrapper) ---


@dataclass(slots=True)
class VectorTag:
    element_type: TypeTag

    def variant(self) -> int:
        return TypeTagVariant.VECTOR

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VectorTag):
            return NotImplemented
        return self.element_type == other.element_type

    def __str__(self) -> str:
        return f"vector<{self.element_type}>"

    @staticmethod
    def deserialize(deserializer: Deserializer) -> VectorTag:
        return VectorTag(TypeTag.deserialize(deserializer))

    def serialize(self, serializer: Serializer) -> None:
        serializer.struct(self.element_type)


@dataclass(slots=True)
class TypeTag:
    value: (
        BoolTag
        | U8Tag
        | U16Tag
        | U32Tag
        | U64Tag
        | U128Tag
        | U256Tag
        | AccountAddressTag
        | SignerTag
        | VectorTag
        | StructTag
    )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TypeTag):
            return NotImplemented
        return self.value.variant() == other.value.variant() and self.value == other.value

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> TypeTag:
        variant = deserializer.uleb128()
        match variant:
            case TypeTagVariant.BOOL:
                return TypeTag(BoolTag.deserialize(deserializer))
            case TypeTagVariant.U8:
                return TypeTag(U8Tag.deserialize(deserializer))
            case TypeTagVariant.U16:
                return TypeTag(U16Tag.deserialize(deserializer))
            case TypeTagVariant.U32:
                return TypeTag(U32Tag.deserialize(deserializer))
            case TypeTagVariant.U64:
                return TypeTag(U64Tag.deserialize(deserializer))
            case TypeTagVariant.U128:
                return TypeTag(U128Tag.deserialize(deserializer))
            case TypeTagVariant.U256:
                return TypeTag(U256Tag.deserialize(deserializer))
            case TypeTagVariant.ACCOUNT_ADDRESS:
                return TypeTag(AccountAddressTag.deserialize(deserializer))
            case TypeTagVariant.SIGNER:
                return TypeTag(SignerTag.deserialize(deserializer))
            case TypeTagVariant.VECTOR:
                return TypeTag(VectorTag.deserialize(deserializer))
            case TypeTagVariant.STRUCT:
                return TypeTag(StructTag.deserialize(deserializer))
            case _:
                raise InvalidTypeTagError(f"Unknown TypeTag variant: {variant}")

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.value.variant())
        serializer.struct(self.value)

    @staticmethod
    def from_str(type_tag: str) -> TypeTag:
        """Parse a Move type-tag string into a :class:`TypeTag`.

        Supports:
            * primitives: ``bool``, ``u8`` … ``u256``, ``address``, ``signer``
            * vectors: ``vector<inner>``
            * structs: ``addr::module::name<...>``

        Raises :class:`InvalidTypeTagError` on malformed input.
        """
        tags, _ = _parse_type_tags(type_tag, 0)
        if len(tags) != 1:
            raise InvalidTypeTagError(f"Expected exactly one type tag, got {len(tags)}")
        return tags[0]


# --- Parser for string representation ---

_PRIMITIVE_TAGS: dict[str, TypeTag] = {}


def _primitive_tag(name: str) -> TypeTag | None:
    """Return the primitive ``TypeTag`` for ``name``, or ``None`` if not primitive."""
    if not _PRIMITIVE_TAGS:
        # Built lazily because TypeTag isn't constructible at module import time
        # for the dataclass slots dance.
        _PRIMITIVE_TAGS.update(
            {
                "bool": TypeTag(BoolTag(False)),
                "u8": TypeTag(U8Tag(0)),
                "u16": TypeTag(U16Tag(0)),
                "u32": TypeTag(U32Tag(0)),
                "u64": TypeTag(U64Tag(0)),
                "u128": TypeTag(U128Tag(0)),
                "u256": TypeTag(U256Tag(0)),
                "address": TypeTag(AccountAddressTag(AccountAddress(b"\x00" * 32))),
                "signer": TypeTag(SignerTag()),
            }
        )
    return _PRIMITIVE_TAGS.get(name)


def _parse_type_tags(type_tag: str, index: int) -> tuple[list[TypeTag], int]:
    """Recursively parse comma-separated tags (struct, primitive, or vector)."""
    name = ""
    tags: list[TypeTag] = []
    inner_tags: list[TypeTag] = []

    while index < len(type_tag):
        letter = type_tag[index]
        index += 1

        if letter == " ":
            continue
        elif letter == "<":
            inner_tags, index = _parse_type_tags(type_tag, index)
        elif letter == ",":
            tags.append(_make_tag(name, inner_tags))
            name = ""
            inner_tags = []
        elif letter == ">":
            break
        else:
            name += letter

    tags.append(_make_tag(name, inner_tags))
    return tags, index


def _make_tag(name: str, inner_tags: list[TypeTag]) -> TypeTag:
    """Resolve a parsed token into a primitive, vector, or struct tag."""
    name = name.strip()
    if name == "vector":
        if len(inner_tags) != 1:
            raise InvalidTypeTagError(
                f"vector<...> expects exactly one type argument, got {len(inner_tags)}"
            )
        return TypeTag(VectorTag(inner_tags[0]))
    primitive = _primitive_tag(name)
    if primitive is not None:
        if inner_tags:
            raise InvalidTypeTagError(f"Primitive type {name!r} does not take type arguments")
        return primitive
    return _make_struct_tag(name, inner_tags)


def _make_struct_tag(name: str, inner_tags: list[TypeTag]) -> TypeTag:
    parts = name.split("::")
    if len(parts) != 3 or not all(parts):
        raise InvalidTypeTagError(f"Invalid struct tag format: {name}")
    return TypeTag(
        StructTag(
            AccountAddress.from_str_relaxed(parts[0]),
            parts[1],
            parts[2],
            inner_tags,
        )
    )
