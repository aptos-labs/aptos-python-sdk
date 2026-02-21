# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
AccountAddress — 32-byte Aptos account address with AIP-40 string formatting.

Spec reference: Aptos SDK Specification v1.0.0, section 01 (Core Types).

String representation follows AIP-40:
  - Special addresses (first 31 bytes zero, last byte < 0x10) use SHORT form:
      0x0  through  0xf
  - All other addresses use LONG form:
      0x + 64 lowercase hex characters (no trimming).
  - All string representations are prefixed with 0x.
"""

import hashlib
from typing import ClassVar

from .bcs import Deserializer, Serializer
from .errors import InvalidAddressError, InvalidHexError, InvalidLengthError


class AuthKeyScheme:
    """Single-byte authentication key scheme tags used during address derivation."""

    Ed25519: bytes = b"\x00"
    MultiEd25519: bytes = b"\x01"
    SingleKey: bytes = b"\x02"
    MultiKey: bytes = b"\x03"
    DeriveObjectAddressFromGuid: bytes = b"\xFD"
    DeriveObjectAddressFromSeed: bytes = b"\xFE"
    DeriveResourceAccountAddress: bytes = b"\xFF"


class AccountAddress:
    """
    A 32-byte Aptos account address.

    Instances are immutable: once created, ``data`` cannot be reassigned.
    Use the ``from_*`` class-level factory methods for construction.
    """

    LENGTH: ClassVar[int] = 32

    # Class-level constants — populated after the class body.
    ZERO: ClassVar["AccountAddress"]
    ONE: ClassVar["AccountAddress"]
    THREE: ClassVar["AccountAddress"]
    FOUR: ClassVar["AccountAddress"]

    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        if len(data) != AccountAddress.LENGTH:
            raise InvalidLengthError(
                f"AccountAddress must be exactly {AccountAddress.LENGTH} bytes, "
                f"got {len(data)}."
            )
        # Store in a private slot; expose via the `data` property.
        object.__setattr__(self, "_data", data)

    # ------------------------------------------------------------------
    # Immutability guard
    # ------------------------------------------------------------------

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AccountAddress is immutable.")

    # ------------------------------------------------------------------
    # Public data property
    # ------------------------------------------------------------------

    @property
    def data(self) -> bytes:
        """The raw 32-byte address data."""
        return object.__getattribute__(self, "_data")

    # ------------------------------------------------------------------
    # Equality, hashing, display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AccountAddress):
            return NotImplemented
        return self.data == other.data

    def __hash__(self) -> int:
        return hash(self.data)

    def __str__(self) -> str:
        """
        AIP-40 canonical string representation.

        Special addresses (``is_special() == True``) are rendered in SHORT form,
        e.g. ``0x1``.  All other addresses are rendered in LONG form,
        e.g. ``0x002098630cfad4734812fa37dc18d9b8d59242feabe49259e26318d468a99584``.
        """
        suffix = self.data.hex()
        if self.is_special():
            suffix = suffix.lstrip("0") or "0"
        return f"0x{suffix}"

    def __repr__(self) -> str:
        return f"AccountAddress({str(self)})"

    # ------------------------------------------------------------------
    # Predicates
    # ------------------------------------------------------------------

    def is_special(self) -> bool:
        """
        Return ``True`` when the address is *special*.

        An address is special when the first 31 bytes are all zero and the
        last byte is less than 16 (``0x10``).  In hex, that matches the
        pattern ``^0x0{63}[0-9a-f]$``, i.e. addresses ``0x0`` through ``0xf``.
        """
        return all(b == 0 for b in self.data[:-1]) and self.data[-1] < 0x10

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @staticmethod
    def from_hex(hex_str: str) -> "AccountAddress":
        """
        Parse an AccountAddress from a hex string — relaxed, spec-compliant.

        Accepted formats (all equivalent to the same address):
        - With or without a ``0x`` / ``0X`` prefix.
        - Case-insensitive hex digits.
        - 1 to 64 hex characters (shorter strings are left-zero-padded to 64 chars).

        Errors:
        - Empty string (after stripping an optional ``0x`` prefix) →
          :class:`~aptos_sdk.errors.InvalidHexError`.
        - More than 64 hex characters →
          :class:`~aptos_sdk.errors.InvalidHexError`.
        - Non-hex characters →
          :class:`~aptos_sdk.errors.InvalidHexError`.
        """
        addr = hex_str

        # Strip optional 0x / 0X prefix.
        if addr.startswith(("0x", "0X")):
            addr = addr[2:]

        if len(addr) == 0:
            raise InvalidHexError(
                "Address hex string is empty (must be 1 to 64 hex characters, "
                "excluding an optional leading '0x')."
            )

        if len(addr) > 64:
            raise InvalidHexError(
                f"Address hex string is too long ({len(addr)} chars); "
                "must be at most 64 hex characters excluding an optional leading '0x'."
            )

        # Left-pad with zeros to reach exactly 64 hex characters.
        addr = addr.zfill(64)

        try:
            raw = bytes.fromhex(addr)
        except ValueError as exc:
            raise InvalidHexError(
                f"Address hex string contains non-hex characters: {hex_str!r}."
            ) from exc

        return AccountAddress(raw)

    @staticmethod
    def from_str(address: str) -> "AccountAddress":
        """
        Parse an AccountAddress using strict AIP-40 rules.

        Only two forms are accepted:
        - **LONG**: ``0x`` followed by exactly 64 lowercase hex characters.
        - **SHORT** (special addresses only): ``0x0`` through ``0xf`` — exactly
          one hex digit, no zero padding.

        All other forms (missing ``0x``, padded short form, short form for
        non-special addresses) raise :class:`~aptos_sdk.errors.InvalidAddressError`.
        """
        if not address.startswith("0x"):
            raise InvalidAddressError(
                "Address must start with '0x' in strict AIP-40 mode."
            )

        out = AccountAddress.from_str_relaxed(address)

        hex_body = address[2:]  # everything after "0x"
        long_form_length = AccountAddress.LENGTH * 2  # 64

        if len(hex_body) == long_form_length:
            # Long form — always valid once we pass from_str_relaxed.
            return out

        # Not long form: only valid for special addresses in single-char short form.
        if not out.is_special():
            raise InvalidAddressError(
                f"Non-special address {address!r} must be in LONG form "
                "(0x + 64 hex characters)."
            )

        # Special address short form: exactly one hex digit after "0x".
        if len(hex_body) != 1:
            raise InvalidAddressError(
                f"Special address {address!r} must be in SHORT form (0x0 to 0xf) "
                "or LONG form (0x + 64 hex characters); padding zeroes are not allowed."
            )

        return out

    @staticmethod
    def from_str_relaxed(address: str) -> "AccountAddress":
        """
        Parse an AccountAddress with relaxed formatting rules.

        Accepts all formats defined by AIP-40:
        - LONG form, with or without ``0x``.
        - SHORT form, with or without ``0x``.
        - Padding zeroes are allowed (e.g. ``0x0f`` is valid).

        Delegates to :meth:`from_hex` for the actual parsing logic.
        """
        return AccountAddress.from_hex(address)

    @staticmethod
    def from_bytes(data: bytes) -> "AccountAddress":
        """
        Construct an AccountAddress directly from 32 raw bytes.

        Raises :class:`~aptos_sdk.errors.InvalidLengthError` if *data* is not
        exactly 32 bytes.
        """
        return AccountAddress(data)

    @staticmethod
    def from_key(public_key: object) -> "AccountAddress":
        """
        Derive an AccountAddress from a public key's authentication key.

        The authentication key is ``SHA3-256(key.to_crypto_bytes() || scheme_byte)``.
        The scheme byte is determined by the concrete key type:

        - :class:`~aptos_sdk.ed25519.PublicKey` → ``0x00`` (Ed25519)
        - :class:`~aptos_sdk.ed25519.MultiPublicKey` → ``0x01`` (MultiEd25519)
        - :class:`~aptos_sdk.asymmetric_crypto_wrapper.PublicKey` → ``0x02`` (SingleKey)
        - :class:`~aptos_sdk.asymmetric_crypto_wrapper.MultiPublicKey` → ``0x03`` (MultiKey)

        Imports are deferred to avoid circular dependencies.

        The *public_key* argument must expose a ``to_crypto_bytes()`` method.
        """
        # Lazy imports to break the circular dependency chain:
        # account_address ← ed25519 ← account_address
        from . import (  # noqa: PLC0415
            crypto_wrapper,
            ed25519,
        )

        hasher = hashlib.sha3_256()
        hasher.update(public_key.to_crypto_bytes())  # type: ignore[attr-defined]

        if isinstance(public_key, ed25519.PublicKey):
            hasher.update(AuthKeyScheme.Ed25519)
        elif isinstance(public_key, ed25519.MultiPublicKey):
            hasher.update(AuthKeyScheme.MultiEd25519)
        elif isinstance(public_key, crypto_wrapper.AnyPublicKey):
            hasher.update(AuthKeyScheme.SingleKey)
        elif isinstance(public_key, crypto_wrapper.MultiKeyPublicKey):
            hasher.update(AuthKeyScheme.MultiKey)
        else:
            raise InvalidAddressError(
                f"Unsupported public key type for address derivation: "
                f"{type(public_key).__name__}."
            )

        return AccountAddress(hasher.digest())

    # ------------------------------------------------------------------
    # Derived address constructors
    # ------------------------------------------------------------------

    @staticmethod
    def for_resource_account(
        creator: "AccountAddress", seed: bytes
    ) -> "AccountAddress":
        """
        Derive the address of a resource account.

        ``SHA3-256(creator.data || seed || 0xFF)``
        """
        hasher = hashlib.sha3_256()
        hasher.update(creator.data)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DeriveResourceAccountAddress)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_named_object(creator: "AccountAddress", seed: bytes) -> "AccountAddress":
        """
        Derive the address of a named object.

        ``SHA3-256(creator.data || seed || 0xFE)``
        """
        hasher = hashlib.sha3_256()
        hasher.update(creator.data)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DeriveObjectAddressFromSeed)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_guid_object(
        creator: "AccountAddress", creation_num: int
    ) -> "AccountAddress":
        """
        Derive the address of a GUID-based object.

        ``SHA3-256(BCS(creation_num as u64) || creator.data || 0xFD)``
        """
        hasher = hashlib.sha3_256()
        serializer = Serializer()
        serializer.u64(creation_num)
        hasher.update(serializer.output())
        hasher.update(creator.data)
        hasher.update(AuthKeyScheme.DeriveObjectAddressFromGuid)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_named_collection(creator: "AccountAddress", name: str) -> "AccountAddress":
        """
        Derive the address of a named token collection.

        Equivalent to :meth:`for_named_object` with ``seed = name.encode()``.
        """
        return AccountAddress.for_named_object(creator, name.encode())

    @staticmethod
    def for_named_token(
        creator: "AccountAddress", collection: str, token: str
    ) -> "AccountAddress":
        """
        Derive the address of a named token within a collection.

        Equivalent to :meth:`for_named_object` with
        ``seed = collection.encode() + b"::" + token.encode()``.
        """
        seed = collection.encode() + b"::" + token.encode()
        return AccountAddress.for_named_object(creator, seed)

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    def to_hex(self) -> str:
        """
        Return the full canonical hex representation: ``0x`` + 64 lowercase hex chars.

        Unlike ``str()``, this never uses the short form even for special addresses.
        """
        return f"0x{self.data.hex()}"

    def to_short_string(self) -> str:
        """
        Return a trimmed hex string with ``0x`` prefix and leading zeros removed.

        This is the SHORT form defined by AIP-40 and is only canonical for
        special addresses.  For non-special addresses callers should prefer
        :meth:`to_hex` or ``str()``.
        """
        trimmed = self.data.hex().lstrip("0") or "0"
        return f"0x{trimmed}"

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Serialize the address as 32 raw bytes (no length prefix)."""
        serializer.fixed_bytes(self.data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "AccountAddress":
        """Deserialize an AccountAddress from 32 raw bytes."""
        return AccountAddress(deserializer.fixed_bytes(AccountAddress.LENGTH))


# ---------------------------------------------------------------------------
# Class-level address constants (set after the class body to avoid forward refs)
# ---------------------------------------------------------------------------

AccountAddress.ZERO = AccountAddress(b"\x00" * 32)
AccountAddress.ONE = AccountAddress(b"\x00" * 31 + b"\x01")
AccountAddress.THREE = AccountAddress(b"\x00" * 31 + b"\x03")
AccountAddress.FOUR = AccountAddress(b"\x00" * 31 + b"\x04")
