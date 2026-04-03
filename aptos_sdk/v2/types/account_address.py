"""32-byte Aptos account address with AIP-40 formatting."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..bcs import Deserializer, Serializer
from ..errors import InvalidAddressError

LENGTH = 32


@dataclass(frozen=True, slots=True)
class AccountAddress:
    """A 32-byte Aptos account address (immutable value type)."""

    address: bytes

    def __post_init__(self) -> None:
        if len(self.address) != LENGTH:
            raise InvalidAddressError(
                f"Expected address of length {LENGTH}, got {len(self.address)}"
            )

    def __str__(self) -> str:
        suffix = self.address.hex()
        if self.is_special():
            suffix = suffix.lstrip("0") or "0"
        return f"0x{suffix}"

    def __repr__(self) -> str:
        return str(self)

    def __hash__(self) -> int:
        return hash(self.address)

    def is_special(self) -> bool:
        """An address is 'special' if the first 31 bytes are zero and the last byte < 0x10."""
        return all(b == 0 for b in self.address[:-1]) and self.address[-1] < 0x10

    # --- Parsing ---

    @staticmethod
    def from_str(address: str) -> AccountAddress:
        """Strict AIP-40 parsing: LONG form or SHORT form for special addresses only."""
        if not address.startswith("0x"):
            raise InvalidAddressError("Hex string must start with a leading 0x.")

        out = AccountAddress.from_str_relaxed(address)

        if len(address) != LENGTH * 2 + 2:
            if not out.is_special():
                raise InvalidAddressError(
                    "Non-special address must be represented as 0x + 64 chars."
                )
            elif len(address) != 3:
                raise InvalidAddressError(
                    "Special address in short form must be 0x0 to 0xf without padding zeroes."
                )

        return out

    @staticmethod
    def from_str_relaxed(address: str) -> AccountAddress:
        """Relaxed parsing: allows short form, padding zeroes, and optional 0x prefix."""
        addr = address
        if addr.startswith("0x"):
            addr = addr[2:]

        if len(addr) < 1:
            raise InvalidAddressError("Hex string is too short, must be 1 to 64 chars.")
        if len(addr) > 64:
            raise InvalidAddressError("Hex string is too long, must be 1 to 64 chars.")

        if len(addr) < LENGTH * 2:
            addr = addr.zfill(LENGTH * 2)

        try:
            return AccountAddress(bytes.fromhex(addr))
        except ValueError as e:
            raise InvalidAddressError(f"Invalid hex in address: {e}") from e

    # --- Derived addresses ---

    @staticmethod
    def for_resource_account(creator: AccountAddress, seed: bytes) -> AccountAddress:
        hasher = hashlib.sha3_256()
        hasher.update(creator.address)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DERIVE_RESOURCE_ACCOUNT)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_named_object(creator: AccountAddress, seed: bytes) -> AccountAddress:
        hasher = hashlib.sha3_256()
        hasher.update(creator.address)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DERIVE_OBJECT_FROM_SEED)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_guid_object(creator: AccountAddress, creation_num: int) -> AccountAddress:
        hasher = hashlib.sha3_256()
        ser = Serializer()
        ser.u64(creation_num)
        hasher.update(ser.output())
        hasher.update(creator.address)
        hasher.update(AuthKeyScheme.DERIVE_OBJECT_FROM_GUID)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_named_collection(
        creator: AccountAddress, collection_name: str
    ) -> AccountAddress:
        return AccountAddress.for_named_object(creator, collection_name.encode())

    @staticmethod
    def for_named_token(
        creator: AccountAddress, collection_name: str, token_name: str
    ) -> AccountAddress:
        return AccountAddress.for_named_object(
            creator, collection_name.encode() + b"::" + token_name.encode()
        )

    # --- BCS ---

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AccountAddress:
        return AccountAddress(deserializer.fixed_bytes(LENGTH))

    def serialize(self, serializer: Serializer) -> None:
        serializer.fixed_bytes(self.address)


class AuthKeyScheme:
    """Authentication key scheme identifiers used in address derivation."""

    ED25519 = b"\x00"
    MULTI_ED25519 = b"\x01"
    SINGLE_KEY = b"\x02"
    MULTI_KEY = b"\x03"
    DERIVE_OBJECT_FROM_GUID = b"\xfd"
    DERIVE_OBJECT_FROM_SEED = b"\xfe"
    DERIVE_RESOURCE_ACCOUNT = b"\xff"
