# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
TypeTag, StructTag, and MoveModuleId — Aptos Move type system representations.

Implements the core type tag hierarchy from the Aptos SDK Specification v1.0.0 (spec 01).
Provides full recursive-descent string parsing for arbitrarily nested generic types.
"""

from enum import IntEnum

from .account_address import AccountAddress
from .bcs import Deserializer, Serializer
from .errors import InvalidModuleIdError, InvalidStructTagError, InvalidTypeTagError

# ---------------------------------------------------------------------------
# TypeTagVariant
# ---------------------------------------------------------------------------


class TypeTagVariant(IntEnum):
    """Numeric discriminants for the TypeTag enum, matching the BCS wire format."""

    BOOL = 0
    U8 = 1
    U64 = 2
    U128 = 3
    ADDRESS = 4
    SIGNER = 5
    VECTOR = 6
    STRUCT = 7
    U16 = 8
    U32 = 9
    U256 = 10


# ---------------------------------------------------------------------------
# TypeTag
# ---------------------------------------------------------------------------


class TypeTag:
    """
    A Move TypeTag — a discriminated union of all Move primitive and compound types.

    The ``value`` attribute holds the inner tag object (e.g. BoolTag, StructTag, etc.).
    """

    value: "BoolTag | U8Tag | U16Tag | U32Tag | U64Tag | U128Tag | U256Tag | AccountAddressTag | SignerTag | VectorTag | StructTag"

    def __init__(
        self,
        value: "BoolTag | U8Tag | U16Tag | U32Tag | U64Tag | U128Tag | U256Tag | AccountAddressTag | SignerTag | VectorTag | StructTag",
    ) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TypeTag):
            return NotImplemented
        return (
            self.value.variant() == other.value.variant() and self.value == other.value
        )

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return self.__str__()

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(int(self.value.variant()))
        serializer.struct(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "TypeTag":
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
            case TypeTagVariant.ADDRESS:
                return TypeTag(AccountAddressTag.deserialize(deserializer))
            case TypeTagVariant.SIGNER:
                return TypeTag(SignerTag.deserialize(deserializer))
            case TypeTagVariant.VECTOR:
                return TypeTag(VectorTag.deserialize(deserializer))
            case TypeTagVariant.STRUCT:
                return TypeTag(StructTag.deserialize(deserializer))
            case _:
                raise InvalidTypeTagError(
                    f"Unknown TypeTag variant: {variant}",
                    error_code="UNKNOWN_VARIANT",
                )

    # ------------------------------------------------------------------
    # String parsing
    # ------------------------------------------------------------------

    @staticmethod
    def from_str(s: str) -> "TypeTag":
        """
        Parse a Move type tag string into a TypeTag.

        Handles all Move primitive types, vectors, structs, and arbitrarily
        nested generic type arguments.

        Supported forms:
        - Primitives: "bool", "u8", "u16", "u32", "u64", "u128", "u256",
                      "address", "signer"
        - Vectors:    "vector<u8>",
                      "vector<0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>>"
        - Structs:    "0x1::aptos_coin::AptosCoin"
        - Generics:   "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
        - Multiple type args: "0x1::foo::Bar<u64, bool>"
        - Whitespace is tolerated and stripped.
        """
        parser = _TypeTagParser(s.strip())
        try:
            tag = parser.parse_type_tag()
        except (InvalidTypeTagError, InvalidStructTagError, InvalidModuleIdError):
            raise
        except Exception as exc:
            raise InvalidTypeTagError(
                f"Failed to parse type tag: {s!r}",
                error_code="PARSE_FAILED",
                cause=exc,
            ) from exc
        if not parser.at_end():
            raise InvalidTypeTagError(
                f"Unexpected trailing characters in type tag: {s!r}",
                error_code="TRAILING_CHARS",
            )
        return tag


# ---------------------------------------------------------------------------
# Primitive tag classes
# ---------------------------------------------------------------------------


class BoolTag:
    """TypeTag for Move ``bool``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.BOOL

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BoolTag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "bool"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass  # No payload for primitive tags

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "BoolTag":
        return BoolTag()


class U8Tag:
    """TypeTag for Move ``u8``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.U8

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, U8Tag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "u8"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "U8Tag":
        return U8Tag()


class U16Tag:
    """TypeTag for Move ``u16``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.U16

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, U16Tag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "u16"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "U16Tag":
        return U16Tag()


class U32Tag:
    """TypeTag for Move ``u32``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.U32

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, U32Tag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "u32"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "U32Tag":
        return U32Tag()


class U64Tag:
    """TypeTag for Move ``u64``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.U64

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, U64Tag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "u64"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "U64Tag":
        return U64Tag()


class U128Tag:
    """TypeTag for Move ``u128``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.U128

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, U128Tag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "u128"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "U128Tag":
        return U128Tag()


class U256Tag:
    """TypeTag for Move ``u256``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.U256

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, U256Tag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "u256"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "U256Tag":
        return U256Tag()


class AccountAddressTag:
    """TypeTag for Move ``address``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.ADDRESS

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AccountAddressTag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "address"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "AccountAddressTag":
        return AccountAddressTag()


class SignerTag:
    """TypeTag for Move ``signer``."""

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.SIGNER

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignerTag):
            return NotImplemented
        return True

    def __str__(self) -> str:
        return "signer"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        pass

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SignerTag":
        return SignerTag()


# ---------------------------------------------------------------------------
# VectorTag
# ---------------------------------------------------------------------------


class VectorTag:
    """
    TypeTag for Move ``vector<T>``.

    The ``value`` attribute holds a ``TypeTag`` representing the element type.
    """

    value: TypeTag

    def __init__(self, element_type: TypeTag) -> None:
        self.value = element_type

    def variant(self) -> TypeTagVariant:
        return TypeTagVariant.VECTOR

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VectorTag):
            return NotImplemented
        return self.value == other.value

    def __str__(self) -> str:
        return f"vector<{self.value}>"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        self.value.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "VectorTag":
        element_type = TypeTag.deserialize(deserializer)
        return VectorTag(element_type)


# ---------------------------------------------------------------------------
# StructTag
# ---------------------------------------------------------------------------


class StructTag:
    """
    TypeTag for a Move struct: ``address::module::Name<TypeArgs...>``.

    Attributes:
        address:   The module's account address.
        module:    The module name (e.g. "coin").
        name:      The struct name (e.g. "CoinStore").
        type_args: Zero or more ``TypeTag`` generic arguments.
    """

    address: AccountAddress
    module: str
    name: str
    type_args: list[TypeTag]

    def __init__(
        self,
        address: AccountAddress,
        module: str,
        name: str,
        type_args: list[TypeTag],
    ) -> None:
        self.address = address
        self.module = module
        self.name = name
        self.type_args = type_args

    def variant(self) -> TypeTagVariant:
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
        base = f"{self.address}::{self.module}::{self.name}"
        if self.type_args:
            args = ", ".join(str(a) for a in self.type_args)
            return f"{base}<{args}>"
        return base

    def __repr__(self) -> str:
        return self.__str__()

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def from_str(s: str) -> "StructTag":
        """
        Parse a struct tag string such as
        ``0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>``.

        Raises:
            InvalidStructTagError: if the string cannot be parsed as a StructTag.
        """
        parser = _TypeTagParser(s.strip())
        try:
            tag = parser.parse_struct_tag()
        except InvalidStructTagError:
            raise
        except Exception as exc:
            raise InvalidStructTagError(
                f"Failed to parse struct tag: {s!r}",
                error_code="PARSE_FAILED",
                cause=exc,
            ) from exc
        if not parser.at_end():
            raise InvalidStructTagError(
                f"Unexpected trailing characters in struct tag: {s!r}",
                error_code="TRAILING_CHARS",
            )
        return tag

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        self.address.serialize(serializer)
        serializer.str(self.module)
        serializer.str(self.name)
        serializer.sequence(self.type_args, Serializer.struct)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "StructTag":
        address = AccountAddress.deserialize(deserializer)
        module = deserializer.str()
        name = deserializer.str()
        type_args = deserializer.sequence(TypeTag.deserialize)
        return StructTag(address, module, name, type_args)


# ---------------------------------------------------------------------------
# MoveModuleId
# ---------------------------------------------------------------------------


class MoveModuleId:
    """
    A fully-qualified Move module identifier: ``address::module_name``.

    Example: ``0x1::coin``.
    """

    address: AccountAddress
    name: str

    def __init__(self, address: AccountAddress, name: str) -> None:
        self.address = address
        self.name = name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MoveModuleId):
            return NotImplemented
        return self.address == other.address and self.name == other.name

    def __str__(self) -> str:
        return f"{self.address}::{self.name}"

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def from_str(s: str) -> "MoveModuleId":
        """
        Parse a module ID string of the form ``0x1::coin``.

        Raises:
            InvalidModuleIdError: if the string is not a valid module identifier.
        """
        parts = s.strip().split("::")
        if len(parts) != 2:
            raise InvalidModuleIdError(
                f"Invalid MoveModuleId: expected 'address::module', got {s!r}",
                error_code="INVALID_FORMAT",
            )
        addr_str, module_name = parts[0].strip(), parts[1].strip()
        if not addr_str:
            raise InvalidModuleIdError(
                f"Invalid MoveModuleId: empty address in {s!r}",
                error_code="EMPTY_ADDRESS",
            )
        if not module_name:
            raise InvalidModuleIdError(
                f"Invalid MoveModuleId: empty module name in {s!r}",
                error_code="EMPTY_MODULE",
            )
        if not _is_valid_identifier(module_name):
            raise InvalidModuleIdError(
                f"Invalid MoveModuleId: module name {module_name!r} is not a valid identifier",
                error_code="INVALID_IDENTIFIER",
            )
        try:
            address = AccountAddress.from_str_relaxed(addr_str)
        except Exception as exc:
            raise InvalidModuleIdError(
                f"Invalid MoveModuleId: cannot parse address {addr_str!r} in {s!r}",
                error_code="INVALID_ADDRESS",
                cause=exc,
            ) from exc
        return MoveModuleId(address, module_name)

    def serialize(self, serializer: Serializer) -> None:
        self.address.serialize(serializer)
        serializer.str(self.name)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MoveModuleId":
        address = AccountAddress.deserialize(deserializer)
        name = deserializer.str()
        return MoveModuleId(address, name)


# ---------------------------------------------------------------------------
# Internal recursive-descent parser
# ---------------------------------------------------------------------------


def _is_valid_identifier(s: str) -> bool:
    """Return True if *s* is a valid Move identifier (non-empty, alphanumeric + _)."""
    if not s:
        return False
    return all(c.isalnum() or c == "_" for c in s)


class _TypeTagParser:
    """
    Recursive-descent parser for Move type tag strings.

    Grammar (simplified):
        type_tag    ::= primitive | "vector" "<" type_tag ">" | struct_tag
        struct_tag  ::= address "::" identifier "::" identifier type_args?
        type_args   ::= "<" type_tag ("," type_tag)* ">"
        primitive   ::= "bool" | "u8" | "u16" | "u32" | "u64" | "u128" | "u256"
                      | "address" | "signer"
    """

    _PRIMITIVES: dict[str, TypeTag] = {}  # populated after class definition

    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def at_end(self) -> bool:
        self._skip_whitespace()
        return self._pos >= len(self._text)

    def _skip_whitespace(self) -> None:
        while self._pos < len(self._text) and self._text[self._pos].isspace():
            self._pos += 1

    def _peek(self) -> str | None:
        self._skip_whitespace()
        if self._pos >= len(self._text):
            return None
        return self._text[self._pos]

    def _consume(self) -> str:
        self._skip_whitespace()
        if self._pos >= len(self._text):
            raise InvalidTypeTagError(
                "Unexpected end of input while parsing type tag",
                error_code="UNEXPECTED_EOF",
            )
        ch = self._text[self._pos]
        self._pos += 1
        return ch

    def _expect(self, ch: str) -> None:
        actual = self._consume()
        if actual != ch:
            raise InvalidTypeTagError(
                f"Expected {ch!r} but got {actual!r} at position {self._pos - 1}",
                error_code="UNEXPECTED_CHAR",
            )

    def _read_word(self) -> str:
        """Read a sequence of identifier/hex characters (letters, digits, _, x)."""
        self._skip_whitespace()
        start = self._pos
        while self._pos < len(self._text) and (
            self._text[self._pos].isalnum() or self._text[self._pos] == "_"
        ):
            self._pos += 1
        return self._text[start : self._pos]

    # ------------------------------------------------------------------
    # Parse entry points
    # ------------------------------------------------------------------

    def parse_type_tag(self) -> TypeTag:
        """Parse a single type tag from the current position."""
        self._skip_whitespace()

        # Peek ahead to decide: address starts with '0' (hex), identifiers
        # start with a letter.
        ch = self._peek()
        if ch is None:
            raise InvalidTypeTagError(
                "Empty type tag string",
                error_code="EMPTY_INPUT",
            )

        # Save position for backtracking on failure.
        saved_pos = self._pos
        word = self._read_word()

        if not word:
            raise InvalidTypeTagError(
                f"Unexpected character {ch!r} while parsing type tag",
                error_code="UNEXPECTED_CHAR",
            )

        # Primitive types
        match word:
            case "bool":
                return TypeTag(BoolTag())
            case "u8":
                return TypeTag(U8Tag())
            case "u16":
                return TypeTag(U16Tag())
            case "u32":
                return TypeTag(U32Tag())
            case "u64":
                return TypeTag(U64Tag())
            case "u128":
                return TypeTag(U128Tag())
            case "u256":
                return TypeTag(U256Tag())
            case "address":
                return TypeTag(AccountAddressTag())
            case "signer":
                return TypeTag(SignerTag())
            case "vector":
                self._expect("<")
                inner = self.parse_type_tag()
                self._expect(">")
                return TypeTag(VectorTag(inner))

        # Not a primitive or vector — must be a struct.
        # ``word`` could be the start of an address (e.g. "0x1") or a
        # plain module/struct name that starts with a letter.
        # Roll back and delegate to the struct parser.
        self._pos = saved_pos

        try:
            struct = self.parse_struct_tag()
        except InvalidStructTagError as exc:
            raise InvalidTypeTagError(
                f"Failed to parse as any known type tag at position {self._pos}",
                error_code="PARSE_FAILED",
                cause=exc,
            ) from exc
        return TypeTag(struct)

    def parse_struct_tag(self) -> StructTag:
        """Parse a struct tag: ``address::module::Name<args...>``."""
        # Parse address portion (may start with "0x" or be a plain hex string).
        addr_str = self._read_address_str()
        if not addr_str:
            raise InvalidStructTagError(
                "Expected an address at the start of a struct tag",
                error_code="MISSING_ADDRESS",
            )
        try:
            address = AccountAddress.from_str_relaxed(addr_str)
        except Exception as exc:
            raise InvalidStructTagError(
                f"Invalid address {addr_str!r} in struct tag",
                error_code="INVALID_ADDRESS",
                cause=exc,
            ) from exc

        self._expect_colons()
        module_name = self._read_identifier("module name")
        self._expect_colons()
        struct_name = self._read_identifier("struct name")

        # Optional type arguments.
        type_args: list[TypeTag] = []
        self._skip_whitespace()
        if self._pos < len(self._text) and self._text[self._pos] == "<":
            self._pos += 1  # consume '<'
            type_args = self._parse_type_arg_list()
            self._expect(">")

        return StructTag(address, module_name, struct_name, type_args)

    # ------------------------------------------------------------------
    # Sub-parsers
    # ------------------------------------------------------------------

    def _read_address_str(self) -> str:
        """
        Read the address portion of a struct tag.

        Addresses in Move type tags are hex strings optionally prefixed with ``0x``.
        We gather characters that are valid hex digits (and the leading ``x`` after
        a ``0``).
        """
        self._skip_whitespace()
        start = self._pos

        # Consume "0x" prefix if present.
        if (
            self._pos + 1 < len(self._text)
            and self._text[self._pos] == "0"
            and self._text[self._pos + 1] in ("x", "X")
        ):
            self._pos += 2  # consume "0x"

        # Consume hex characters.
        while (
            self._pos < len(self._text)
            and self._text[self._pos] in "0123456789abcdefABCDEF"
        ):
            self._pos += 1

        return self._text[start : self._pos]

    def _expect_colons(self) -> None:
        """Consume `::` separator, raising InvalidStructTagError on failure."""
        self._skip_whitespace()
        if (
            self._pos + 1 < len(self._text)
            and self._text[self._pos] == ":"
            and self._text[self._pos + 1] == ":"
        ):
            self._pos += 2
        else:
            snippet = self._text[self._pos : self._pos + 5]
            raise InvalidStructTagError(
                f"Expected '::' separator, got {snippet!r} at position {self._pos}",
                error_code="MISSING_SEPARATOR",
            )

    def _read_identifier(self, what: str) -> str:
        """Read a Move identifier (alphanumeric + underscore, non-empty)."""
        self._skip_whitespace()
        start = self._pos
        while self._pos < len(self._text) and (
            self._text[self._pos].isalnum() or self._text[self._pos] == "_"
        ):
            self._pos += 1
        ident = self._text[start : self._pos]
        if not ident:
            snippet = self._text[self._pos : self._pos + 10]
            raise InvalidStructTagError(
                f"Expected {what}, got {snippet!r} at position {self._pos}",
                error_code="MISSING_IDENTIFIER",
            )
        return ident

    def _parse_type_arg_list(self) -> list[TypeTag]:
        """
        Parse a comma-separated list of type tags inside angle brackets.

        The opening '<' has already been consumed.  This method reads until the
        matching '>' is seen (without consuming it).
        """
        args: list[TypeTag] = []
        self._skip_whitespace()

        # Handle empty type arg list "<>" gracefully.
        if self._pos < len(self._text) and self._text[self._pos] == ">":
            return args

        args.append(self.parse_type_tag())
        while True:
            self._skip_whitespace()
            if self._pos >= len(self._text):
                raise InvalidTypeTagError(
                    "Unexpected end of input inside type argument list",
                    error_code="UNEXPECTED_EOF",
                )
            ch = self._text[self._pos]
            if ch == ">":
                break
            if ch == ",":
                self._pos += 1  # consume ','
                args.append(self.parse_type_tag())
            else:
                raise InvalidTypeTagError(
                    f"Expected ',' or '>' in type argument list, got {ch!r} at position {self._pos}",
                    error_code="UNEXPECTED_CHAR",
                )
        return args
