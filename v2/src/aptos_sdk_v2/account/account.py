"""Account — a keypair with associated address for signing transactions."""

from __future__ import annotations

from ..crypto.authentication_key import AuthenticationKey
from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..crypto.keys import PrivateKey, PublicKey, Signature
from ..crypto.mnemonic import (
    DEFAULT_DERIVATION_PATH,
    derive_ed25519_private_key,
    derive_secp256k1_private_key,
)
from ..crypto.secp256k1 import Secp256k1PrivateKey
from ..crypto.single_key import AnyPublicKey
from ..transactions.authenticator import AccountAuthenticator
from ..transactions.raw_transaction import RawTransaction
from ..types.account_address import AccountAddress


class Account:
    """An Aptos account: a private key, public key, and derived address."""

    __slots__ = ("_private_key", "_address")

    def __init__(self, private_key: PrivateKey, address: AccountAddress) -> None:
        self._private_key = private_key
        self._address = address

    @staticmethod
    def generate() -> Account:
        """Generate a new Ed25519 account."""
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        auth_key = AuthenticationKey.from_public_key(pub)
        return Account(key, auth_key.account_address())

    @staticmethod
    def generate_secp256k1() -> Account:
        """Generate a new Secp256k1 account."""
        key = Secp256k1PrivateKey.generate()
        pub = AnyPublicKey(key.public_key())
        auth_key = AuthenticationKey.from_public_key(pub)
        return Account(key, auth_key.account_address())

    @staticmethod
    def from_private_key(key: PrivateKey) -> Account:
        """Create an account from an existing private key."""
        pub = key.public_key()
        if isinstance(pub, Ed25519PublicKey):
            auth_key = AuthenticationKey.from_public_key(pub)
        else:
            auth_key = AuthenticationKey.from_public_key(AnyPublicKey(pub))
        return Account(key, auth_key.account_address())

    @staticmethod
    def from_mnemonic(
        phrase: str,
        path: str = DEFAULT_DERIVATION_PATH,
        *,
        secp256k1: bool = False,
    ) -> Account:
        """Derive an account from a BIP-39 mnemonic phrase."""
        key: PrivateKey
        if secp256k1:
            key = derive_secp256k1_private_key(phrase, path)
        else:
            key = derive_ed25519_private_key(phrase, path)
        return Account.from_private_key(key)

    @property
    def address(self) -> AccountAddress:
        return self._address

    @property
    def public_key(self) -> PublicKey:
        return self._private_key.public_key()

    @property
    def private_key(self) -> PrivateKey:
        return self._private_key

    def sign(self, data: bytes) -> Signature:
        return self._private_key.sign(data)

    def sign_transaction(self, raw_txn: RawTransaction) -> AccountAuthenticator:
        return raw_txn.sign(self._private_key)
