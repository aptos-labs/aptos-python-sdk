"""Account — a keypair with associated address for signing transactions."""

from __future__ import annotations

from ..crypto.authentication_key import AuthenticationKey
from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..crypto.keys import PrivateKey, PublicKey, Signature
from ..crypto.mnemonic import (
    DEFAULT_DERIVATION_PATH,
    derive_ed25519_private_key,
    derive_secp256k1_private_key,
    derive_slh_dsa_sha2_128s_private_key,
)
from ..crypto.secp256k1 import Secp256k1PrivateKey
from ..crypto.single_key import AnyPublicKey
from ..crypto.slh_dsa_sha2_128s import SlhDsaSha2128sPrivateKey
from ..transactions.authenticator import AccountAuthenticator
from ..transactions.raw_transaction import RawTransaction
from ..types.account_address import AccountAddress


class Account:
    """An Aptos account: a private key, public key, and derived address."""

    __slots__ = ("_private_key", "_address")

    def __init__(self, private_key: PrivateKey, address: AccountAddress) -> None:
        self._private_key = private_key
        self._address = address

    @classmethod
    def generate(cls) -> Account:
        """Generate a new Ed25519 account."""
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        auth_key = AuthenticationKey.from_public_key(pub)
        return cls(key, auth_key.account_address())

    @classmethod
    def generate_secp256k1(cls) -> Account:
        """Generate a new Secp256k1 account."""
        key = Secp256k1PrivateKey.generate()
        pub = AnyPublicKey(key.public_key())
        auth_key = AuthenticationKey.from_public_key(pub)
        return cls(key, auth_key.account_address())

    @classmethod
    def generate_slh_dsa_sha2_128s(cls) -> Account:
        """Generate a new SLH-DSA-SHA2-128s (post-quantum) account."""
        key = SlhDsaSha2128sPrivateKey.generate()
        pub = AnyPublicKey(key.public_key())
        auth_key = AuthenticationKey.from_public_key(pub)
        return cls(key, auth_key.account_address())

    @classmethod
    def from_private_key(cls, key: PrivateKey) -> Account:
        """Create an account from an existing private key."""
        pub = key.public_key()
        if isinstance(pub, Ed25519PublicKey):
            auth_key = AuthenticationKey.from_public_key(pub)
        else:
            auth_key = AuthenticationKey.from_public_key(AnyPublicKey(pub))
        return cls(key, auth_key.account_address())

    @classmethod
    def from_mnemonic(
        cls,
        phrase: str,
        path: str = DEFAULT_DERIVATION_PATH,
        *,
        secp256k1: bool = False,
        slh_dsa_sha2_128s: bool = False,
    ) -> Account:
        """Derive an account from a BIP-39 mnemonic phrase."""
        if secp256k1 and slh_dsa_sha2_128s:
            raise ValueError("Only one of secp256k1 / slh_dsa_sha2_128s may be selected")
        key: PrivateKey
        if slh_dsa_sha2_128s:
            key = derive_slh_dsa_sha2_128s_private_key(phrase, path)
        elif secp256k1:
            key = derive_secp256k1_private_key(phrase, path)
        else:
            key = derive_ed25519_private_key(phrase, path)
        return cls.from_private_key(key)

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
