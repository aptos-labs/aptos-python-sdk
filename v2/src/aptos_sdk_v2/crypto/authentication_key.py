"""AuthenticationKey — derives account addresses from public keys."""

from __future__ import annotations

import hashlib

from ..types.account_address import AccountAddress, AuthKeyScheme
from .ed25519 import Ed25519PublicKey
from .keys import PublicKey
from .single_key import AnyPublicKey


class AuthenticationKey:
    """Derives an account address from a public key using the appropriate scheme."""

    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        self._data = data

    @staticmethod
    def from_public_key(key: PublicKey) -> AuthenticationKey:
        hasher = hashlib.sha3_256()
        hasher.update(key.to_crypto_bytes())

        if isinstance(key, Ed25519PublicKey):
            hasher.update(AuthKeyScheme.ED25519)
        elif isinstance(key, AnyPublicKey):
            hasher.update(AuthKeyScheme.SINGLE_KEY)
        else:
            raise ValueError(f"Unsupported public key type: {type(key).__name__}")

        return AuthenticationKey(hasher.digest())

    def account_address(self) -> AccountAddress:
        return AccountAddress(self._data)

    def hex(self) -> str:
        return f"0x{self._data.hex()}"
