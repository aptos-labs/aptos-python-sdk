"""Unit tests for BIP-39 mnemonic generation and key derivation."""

import pytest

from aptos_sdk_v2.crypto.mnemonic import (
    derive_ed25519_private_key,
    generate_mnemonic,
    validate_mnemonic,
)
from aptos_sdk_v2.errors import InvalidMnemonicError


class TestMnemonicGeneration:
    def test_generate_12_words(self):
        phrase = generate_mnemonic(12)
        words = phrase.split()
        assert len(words) == 12
        assert validate_mnemonic(phrase)

    def test_generate_24_words(self):
        phrase = generate_mnemonic(24)
        words = phrase.split()
        assert len(words) == 24
        assert validate_mnemonic(phrase)

    def test_invalid_word_count(self):
        with pytest.raises(ValueError):
            generate_mnemonic(15)


class TestMnemonicValidation:
    def test_valid_phrase(self):
        phrase = generate_mnemonic()
        assert validate_mnemonic(phrase)

    def test_invalid_phrase(self):
        assert not validate_mnemonic("invalid mnemonic phrase that is not real")


class TestKeyDerivation:
    def test_derive_ed25519_deterministic(self):
        phrase = generate_mnemonic()
        key1 = derive_ed25519_private_key(phrase)
        key2 = derive_ed25519_private_key(phrase)
        assert key1 == key2

    def test_different_phrase_different_key(self):
        phrase1 = generate_mnemonic()
        phrase2 = generate_mnemonic()
        key1 = derive_ed25519_private_key(phrase1)
        key2 = derive_ed25519_private_key(phrase2)
        assert key1 != key2

    def test_invalid_phrase_raises(self):
        with pytest.raises(InvalidMnemonicError):
            derive_ed25519_private_key("not a valid mnemonic phrase")

    def test_derive_secp256k1(self):
        from aptos_sdk_v2.crypto.mnemonic import derive_secp256k1_private_key
        from aptos_sdk_v2.crypto.secp256k1 import Secp256k1PrivateKey

        phrase = generate_mnemonic()
        key = derive_secp256k1_private_key(phrase)
        assert isinstance(key, Secp256k1PrivateKey)

    def test_derive_secp256k1_deterministic(self):
        from aptos_sdk_v2.crypto.mnemonic import derive_secp256k1_private_key

        phrase = generate_mnemonic()
        k1 = derive_secp256k1_private_key(phrase)
        k2 = derive_secp256k1_private_key(phrase)
        assert k1 == k2

    def test_derive_secp256k1_invalid_phrase(self):
        from aptos_sdk_v2.crypto.mnemonic import derive_secp256k1_private_key

        with pytest.raises(InvalidMnemonicError):
            derive_secp256k1_private_key("invalid phrase here")

    def test_derive_ed25519_bad_path(self):
        phrase = generate_mnemonic()
        with pytest.raises(InvalidMnemonicError, match="Invalid derivation"):
            derive_ed25519_private_key(phrase, "bad/path")

    def test_derive_secp256k1_bad_path(self):
        from aptos_sdk_v2.crypto.mnemonic import derive_secp256k1_private_key

        phrase = generate_mnemonic()
        with pytest.raises(InvalidMnemonicError, match="Invalid derivation"):
            derive_secp256k1_private_key(phrase, "bad/path")
