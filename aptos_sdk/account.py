# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Account management for the Aptos Python SDK (Spec 04).

An :class:`Account` pairs an :class:`~aptos_sdk.account_address.AccountAddress`
with a :class:`~aptos_sdk.asymmetric_crypto.PrivateKey`.  It is the primary
entry point for key generation, transaction signing, and JSON persistence.

Supported key types
-------------------
- **Ed25519** (default, P0): standard Aptos account authentication.
- **Secp256k1** (P1): single-key authentication via the ``AnyPublicKey`` wrapper.

Key derivation
--------------
For Ed25519 accounts the address is derived directly::

    address = AccountAddress.from_key(ed25519_public_key)  # scheme byte 0x00

For Secp256k1 accounts the public key is first wrapped in an
:class:`~aptos_sdk.crypto_wrapper.AnyPublicKey` and the SingleKey scheme
byte (``0x02``) is used::

    address = AccountAddress.from_key(AnyPublicKey(secp256k1_public_key))

BIP-39 / HD Wallet support (P1)
--------------------------------
:meth:`Account.from_mnemonic` derives an Ed25519 account from a BIP-39
mnemonic phrase using the standard Aptos path ``m/44'/637'/0'/0'/0'``.
The ``mnemonic`` package must be installed for mnemonic *generation*; seed
derivation and SLIP-0010 derivation are implemented with the Python stdlib
and do not require the package.

JSON persistence
----------------
:meth:`Account.load` / :meth:`Account.store` read and write a minimal JSON
file containing the ``account_address`` and ``private_key`` (AIP-80 format).
Only Ed25519 keys are currently supported for persistence.
"""

import json

from . import crypto_wrapper, ed25519, secp256k1_ecdsa
from .account_address import AccountAddress
from .asymmetric_crypto import PrivateKey, PrivateKeyVariant, Signature


class Account:
    """
    An Aptos account with an address and a signing private key.

    Parameters
    ----------
    address:
        The on-chain :class:`~aptos_sdk.account_address.AccountAddress`
        associated with this account.
    private_key:
        The private key used to sign transactions.  Must satisfy the
        :class:`~aptos_sdk.asymmetric_crypto.PrivateKey` protocol.

    Attributes
    ----------
    address : AccountAddress
        The account's on-chain address.
    private_key : PrivateKey
        The private key for signing operations.
    """

    address: AccountAddress
    private_key: PrivateKey

    def __init__(self, address: AccountAddress, private_key: PrivateKey) -> None:
        self.address = address
        self.private_key = private_key

    # ------------------------------------------------------------------
    # Equality and display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Account):
            return NotImplemented
        return self.address == other.address and self.private_key == other.private_key

    def __repr__(self) -> str:
        return f"Account(address={self.address!r}, private_key={self.private_key!r})"

    def __str__(self) -> str:
        return f"Account(address={self.address})"

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @staticmethod
    def generate(scheme: PrivateKeyVariant = PrivateKeyVariant.ED25519) -> "Account":
        """
        Generate a new account with a freshly generated private key.

        Parameters
        ----------
        scheme:
            The key algorithm to use.  Defaults to
            :attr:`~PrivateKeyVariant.ED25519`.

        Returns
        -------
        Account
            A new account backed by a randomly generated key.
        """
        if scheme == PrivateKeyVariant.ED25519:
            ed_key = ed25519.Ed25519PrivateKey.generate()
            address = AccountAddress.from_key(ed_key.public_key())
            return Account(address, ed_key)  # type: ignore[arg-type]

        if scheme == PrivateKeyVariant.SECP256K1:
            secp_key = secp256k1_ecdsa.Secp256k1PrivateKey.generate()
            any_pubkey = crypto_wrapper.AnyPublicKey(secp_key.public_key())
            address = AccountAddress.from_key(any_pubkey)
            return Account(address, secp_key)  # type: ignore[arg-type]

        raise ValueError(f"Unsupported PrivateKeyVariant: {scheme!r}")

    @staticmethod
    def from_private_key(
        key: PrivateKey,
        *,
        address: AccountAddress | None = None,
    ) -> "Account":
        """
        Construct an account from an existing private key.

        Parameters
        ----------
        key:
            A concrete private key (:class:`~aptos_sdk.ed25519.Ed25519PrivateKey`
            or :class:`~aptos_sdk.secp256k1_ecdsa.Secp256k1PrivateKey`).
        address:
            Override the derived address.  When ``None`` (default), the
            address is derived from the key's public key using the
            appropriate authentication-key scheme.

        Returns
        -------
        Account
        """
        if address is None:
            address = Account._derive_address(key)
        return Account(address, key)

    @staticmethod
    def from_mnemonic(
        mnemonic: str,
        path: str = "m/44'/637'/0'/0'/0'",
    ) -> "Account":
        """
        Derive an Ed25519 account from a BIP-39 mnemonic phrase.

        Uses SLIP-0010 hardened derivation with the provided BIP-44 path.
        The ``mnemonic`` package is not required for this method; it only
        performs PBKDF2 seed derivation and SLIP-0010 child-key derivation.

        Parameters
        ----------
        mnemonic:
            A BIP-39 mnemonic phrase (space-separated words).
        path:
            BIP-44 derivation path.  All segments must be hardened.
            Defaults to the standard Aptos path ``"m/44'/637'/0'/0'/0'"``.

        Returns
        -------
        Account
            An Ed25519 account derived from the mnemonic.

        Raises
        ------
        InvalidInputError
            If *path* is not a valid hardened derivation path.
        """
        # Lazy import to avoid circular dependency and to keep the mnemonic
        # module optional at the package level.
        from .mnemonic import derive_key, mnemonic_to_seed  # noqa: PLC0415

        seed = mnemonic_to_seed(mnemonic)
        key_bytes = derive_key(seed, path)
        private_key = ed25519.Ed25519PrivateKey.from_bytes(key_bytes)
        return Account.from_private_key(private_key)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, message: bytes) -> Signature:
        """
        Sign *message* with this account's private key.

        Parameters
        ----------
        message:
            The raw bytes to sign.

        Returns
        -------
        Signature
            The resulting signature.
        """
        return self.private_key.sign(message)

    def sign_transaction(self, transaction: object) -> object:
        """
        Sign a raw transaction and return an ``AccountAuthenticator``.

        This is a convenience wrapper that delegates to the transaction's
        ``sign`` method.  The concrete authenticator type depends on the
        transaction and key type and is resolved at Phase 3.

        Parameters
        ----------
        transaction:
            A :class:`~aptos_sdk.transactions.RawTransactionInternal` or
            compatible transaction object exposing a ``sign(private_key)``
            method.

        Returns
        -------
        AccountAuthenticator
            The authenticator produced by ``transaction.sign(self.private_key)``.
        """
        # Lazy import to avoid a circular dependency with transactions.py,
        # which will be implemented in Phase 3.
        return transaction.sign(self.private_key)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Key accessors
    # ------------------------------------------------------------------

    def public_key(self) -> object:
        """
        Return the public key for this account.

        Returns
        -------
        PublicKey
            The public key corresponding to :attr:`private_key`.
        """
        return self.private_key.public_key()

    def auth_key(self) -> str:
        """
        Return the authentication key as a hex string.

        For Ed25519 keys the auth key is derived directly from the public key.
        For Secp256k1 keys the public key is first wrapped in
        :class:`~aptos_sdk.crypto_wrapper.AnyPublicKey` before derivation.

        Returns
        -------
        str
            The authentication key as a ``0x``-prefixed 64-character lowercase
            hex string (the string form of the derived ``AccountAddress``).
        """
        derived = Account._derive_address(self.private_key)
        return str(derived)

    # ------------------------------------------------------------------
    # JSON persistence
    # ------------------------------------------------------------------

    @staticmethod
    def load(path: str) -> "Account":
        """
        Load an account from a JSON file previously created by :meth:`store`.

        The JSON file must contain at least two keys:

        - ``"account_address"``: the account address as a hex string.
        - ``"private_key"``: the Ed25519 private key in AIP-80 format or
          plain hex.

        Parameters
        ----------
        path:
            File-system path to the JSON file.

        Returns
        -------
        Account

        Raises
        ------
        OSError
            If the file cannot be opened.
        KeyError
            If the JSON file is missing required keys.
        InvalidPrivateKeyError
            If the private key value is malformed.
        InvalidAddressError
            If the account address value is malformed.
        """
        with open(path) as fh:
            data = json.load(fh)

        address = AccountAddress.from_hex(data["account_address"])
        private_key = ed25519.Ed25519PrivateKey.from_hex(
            data["private_key"], strict=False
        )
        return Account(address, private_key)  # type: ignore[arg-type]

    def store(self, path: str) -> None:
        """
        Persist this account to a JSON file.

        The file contains:

        - ``"account_address"``: AIP-40 canonical address string.
        - ``"private_key"``: AIP-80 private key string.

        Parameters
        ----------
        path:
            Destination file-system path.  The file is created or overwritten.

        Raises
        ------
        NotImplementedError
            If the private key is not an
            :class:`~aptos_sdk.ed25519.Ed25519PrivateKey` (other key types
            are not yet supported for persistence).
        OSError
            If the file cannot be written.
        """
        if not isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            raise NotImplementedError(
                "Account.store() currently only supports Ed25519 keys. "
                f"Got {type(self.private_key).__name__!r}."
            )
        data = {
            "account_address": str(self.address),
            "private_key": self.private_key.to_aip80(),
        }
        with open(path, "w") as fh:
            json.dump(data, fh)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_address(key: PrivateKey) -> AccountAddress:
        """
        Derive the ``AccountAddress`` for *key* using the appropriate scheme.

        Ed25519 keys are passed directly to
        :meth:`~aptos_sdk.account_address.AccountAddress.from_key` (scheme
        byte ``0x00``).

        Secp256k1 keys are wrapped in
        :class:`~aptos_sdk.crypto_wrapper.AnyPublicKey` first (scheme
        byte ``0x02`` — SingleKey).

        Parameters
        ----------
        key:
            A concrete private key instance.

        Returns
        -------
        AccountAddress
        """
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return AccountAddress.from_key(key.public_key())
        if isinstance(key, secp256k1_ecdsa.Secp256k1PrivateKey):
            any_pubkey = crypto_wrapper.AnyPublicKey(key.public_key())
            return AccountAddress.from_key(any_pubkey)
        # Fallback: try direct derivation; will raise if key type is unknown.
        return AccountAddress.from_key(key.public_key())  # type: ignore[arg-type]
