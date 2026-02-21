# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.account — Account generation, key derivation, signing,
JSON persistence.
"""

import json

import pytest

from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.asymmetric_crypto import PrivateKeyVariant
from aptos_sdk.ed25519 import Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature
from aptos_sdk.secp256k1_ecdsa import Secp256k1PrivateKey, Secp256k1PublicKey

# ---------------------------------------------------------------------------
# Account.generate
# ---------------------------------------------------------------------------


class TestAccountGenerate:
    def test_generate_ed25519_default(self):
        account = Account.generate()
        assert isinstance(account.private_key, Ed25519PrivateKey)
        assert isinstance(account.address, AccountAddress)

    def test_generate_ed25519_explicit(self):
        account = Account.generate(scheme=PrivateKeyVariant.ED25519)
        assert isinstance(account.private_key, Ed25519PrivateKey)

    def test_generate_secp256k1(self):
        account = Account.generate(scheme=PrivateKeyVariant.SECP256K1)
        assert isinstance(account.private_key, Secp256k1PrivateKey)
        assert isinstance(account.address, AccountAddress)

    def test_generate_produces_unique_accounts(self):
        a = Account.generate()
        b = Account.generate()
        assert a.address != b.address
        assert a.private_key != b.private_key

    def test_generate_invalid_scheme_raises(self):
        with pytest.raises(ValueError):
            Account.generate(scheme=99)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Account.from_private_key
# ---------------------------------------------------------------------------


class TestAccountFromPrivateKey:
    def test_from_ed25519_key(self):
        key = Ed25519PrivateKey.generate()
        account = Account.from_private_key(key)
        assert account.private_key == key
        assert isinstance(account.address, AccountAddress)

    def test_from_secp256k1_key(self):
        key = Secp256k1PrivateKey.generate()
        account = Account.from_private_key(key)
        assert account.private_key == key
        assert isinstance(account.address, AccountAddress)

    def test_address_override(self):
        key = Ed25519PrivateKey.generate()
        custom_addr = AccountAddress.ONE
        account = Account.from_private_key(key, address=custom_addr)
        assert account.address == custom_addr

    def test_ed25519_address_derivation_consistent(self):
        key = Ed25519PrivateKey.generate()
        account1 = Account.from_private_key(key)
        account2 = Account.from_private_key(key)
        assert account1.address == account2.address


# ---------------------------------------------------------------------------
# Account.from_mnemonic
# ---------------------------------------------------------------------------


class TestAccountFromMnemonic:
    KNOWN_MNEMONIC = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    def test_from_mnemonic_returns_account(self):
        account = Account.from_mnemonic(self.KNOWN_MNEMONIC)
        assert isinstance(account, Account)
        assert isinstance(account.private_key, Ed25519PrivateKey)
        assert isinstance(account.address, AccountAddress)

    def test_from_mnemonic_deterministic(self):
        a = Account.from_mnemonic(self.KNOWN_MNEMONIC)
        b = Account.from_mnemonic(self.KNOWN_MNEMONIC)
        assert a.address == b.address
        assert a.private_key == b.private_key

    def test_from_mnemonic_custom_path(self):
        default = Account.from_mnemonic(self.KNOWN_MNEMONIC)
        custom = Account.from_mnemonic(self.KNOWN_MNEMONIC, path="m/44'/637'/0'/0'/1'")
        assert default.address != custom.address


# ---------------------------------------------------------------------------
# Account signing
# ---------------------------------------------------------------------------


class TestAccountSigning:
    def test_sign_produces_signature(self):
        account = Account.generate()
        sig = account.sign(b"hello aptos")
        assert isinstance(sig, Ed25519Signature)
        assert len(sig.to_bytes()) == 64

    def test_sign_ed25519_produces_ed25519_signature(self):
        account = Account.generate(scheme=PrivateKeyVariant.ED25519)
        sig = account.sign(b"test message")
        assert isinstance(sig, Ed25519Signature)

    def test_sign_valid_signature_verifies(self):
        account = Account.generate(scheme=PrivateKeyVariant.ED25519)
        msg = b"verify this"
        sig = account.sign(msg)
        pub = account.public_key()
        assert isinstance(pub, Ed25519PublicKey)
        assert pub.verify(msg, sig)

    def test_sign_secp256k1_signature_verifies(self):
        from aptos_sdk.secp256k1_ecdsa import Secp256k1Signature

        account = Account.generate(scheme=PrivateKeyVariant.SECP256K1)
        msg = b"secp256k1 message"
        sig = account.sign(msg)
        assert isinstance(sig, Secp256k1Signature)
        pub = account.public_key()
        assert isinstance(pub, Secp256k1PublicKey)
        assert pub.verify(msg, sig)


# ---------------------------------------------------------------------------
# Account.public_key
# ---------------------------------------------------------------------------


class TestAccountPublicKey:
    def test_ed25519_public_key_type(self):
        account = Account.generate(scheme=PrivateKeyVariant.ED25519)
        pub = account.public_key()
        assert isinstance(pub, Ed25519PublicKey)

    def test_secp256k1_public_key_type(self):
        account = Account.generate(scheme=PrivateKeyVariant.SECP256K1)
        pub = account.public_key()
        assert isinstance(pub, Secp256k1PublicKey)


# ---------------------------------------------------------------------------
# Account equality
# ---------------------------------------------------------------------------


class TestAccountEquality:
    def test_same_account_equal(self):
        key = Ed25519PrivateKey.generate()
        account = Account.from_private_key(key)
        account2 = Account.from_private_key(key)
        assert account == account2

    def test_different_accounts_not_equal(self):
        a = Account.generate()
        b = Account.generate()
        assert a != b

    def test_not_equal_to_non_account(self):
        a = Account.generate()
        result = a.__eq__("not an account")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# Account.store / Account.load (JSON persistence)
# ---------------------------------------------------------------------------


class TestAccountJsonPersistence:
    def test_store_and_load_roundtrip(self, tmp_path):
        account = Account.generate(scheme=PrivateKeyVariant.ED25519)
        path = str(tmp_path / "account.json")
        account.store(path)
        loaded = Account.load(path)
        assert loaded == account

    def test_store_creates_valid_json(self, tmp_path):
        account = Account.generate(scheme=PrivateKeyVariant.ED25519)
        path = str(tmp_path / "account.json")
        account.store(path)
        with open(path) as f:
            data = json.load(f)
        assert "account_address" in data
        assert "private_key" in data

    def test_stored_private_key_is_aip80(self, tmp_path):
        account = Account.generate(scheme=PrivateKeyVariant.ED25519)
        path = str(tmp_path / "account.json")
        account.store(path)
        with open(path) as f:
            data = json.load(f)
        assert data["private_key"].startswith("ed25519-priv-0x")

    def test_store_secp256k1_raises_not_implemented(self, tmp_path):
        account = Account.generate(scheme=PrivateKeyVariant.SECP256K1)
        path = str(tmp_path / "account.json")
        with pytest.raises(NotImplementedError):
            account.store(path)


# ---------------------------------------------------------------------------
# Account repr
# ---------------------------------------------------------------------------


class TestAccountRepr:
    def test_repr_does_not_expose_private_key(self):
        account = Account.generate()
        r = repr(account)
        # The repr should include the private_key's repr (which masks key material)
        assert "***" in r

    def test_str_contains_address(self):
        account = Account.generate()
        s = str(account)
        assert "Account" in s

    def test_auth_key_is_hex_string(self):
        account = Account.generate()
        auth = account.auth_key()
        assert auth.startswith("0x")
        assert len(auth) == 66  # "0x" + 64 hex chars (32 bytes)
