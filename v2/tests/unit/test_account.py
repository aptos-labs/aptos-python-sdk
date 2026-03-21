"""Unit tests for Account class — all key types, construction, signing."""

import pytest

from aptos_sdk_v2 import Account
from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from aptos_sdk_v2.crypto.mnemonic import generate_mnemonic
from aptos_sdk_v2.crypto.secp256k1 import Secp256k1PrivateKey
from aptos_sdk_v2.crypto.single_key import AnyPublicKey
from aptos_sdk_v2.transactions.authenticator import AccountAuthenticator
from aptos_sdk_v2.transactions.payload import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk_v2.transactions.raw_transaction import RawTransaction
from aptos_sdk_v2.types.account_address import AccountAddress


class TestGenerate:
    def test_generate_ed25519(self):
        acct = Account.generate()
        assert isinstance(acct.private_key, Ed25519PrivateKey)
        assert isinstance(acct.public_key, Ed25519PublicKey)
        assert isinstance(acct.address, AccountAddress)

    def test_generate_secp256k1(self):
        acct = Account.generate_secp256k1()
        assert isinstance(acct.private_key, Secp256k1PrivateKey)
        assert isinstance(acct.address, AccountAddress)

    def test_two_generates_are_different(self):
        a = Account.generate()
        b = Account.generate()
        assert a.address != b.address


class TestFromPrivateKey:
    def test_from_ed25519_key(self):
        key = Ed25519PrivateKey.generate()
        acct = Account.from_private_key(key)
        assert acct.private_key == key
        assert isinstance(acct.public_key, Ed25519PublicKey)

    def test_from_secp256k1_key(self):
        key = Secp256k1PrivateKey.generate()
        acct = Account.from_private_key(key)
        assert acct.private_key == key


class TestFromMnemonic:
    def test_ed25519_mnemonic(self):
        phrase = generate_mnemonic()
        acct = Account.from_mnemonic(phrase)
        assert isinstance(acct.private_key, Ed25519PrivateKey)

    def test_secp256k1_mnemonic(self):
        phrase = generate_mnemonic()
        acct = Account.from_mnemonic(phrase, secp256k1=True)
        assert isinstance(acct.private_key, Secp256k1PrivateKey)

    def test_deterministic(self):
        phrase = generate_mnemonic()
        a = Account.from_mnemonic(phrase)
        b = Account.from_mnemonic(phrase)
        assert a.address == b.address


class TestSign:
    def test_sign_bytes(self):
        acct = Account.generate()
        sig = acct.sign(b"hello")
        assert acct.public_key.verify(b"hello", sig)

    def test_sign_transaction(self):
        sender = Account.generate()
        recipient = Account.generate()

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [],
            [
                TransactionArgument(recipient.address, lambda s, v: s.struct(v)),
                TransactionArgument(1000, lambda s, v: s.u64(v)),
            ],
        )
        raw_txn = RawTransaction(
            sender.address, 0, TransactionPayload(payload), 2000, 0, 999999999, 4
        )
        auth = sender.sign_transaction(raw_txn)
        assert isinstance(auth, AccountAuthenticator)
