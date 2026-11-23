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


class TestBipUtilsCompatibilityVectors:
    """Fixed vectors generated with bip-utils 2.12.2 before its removal.

    Pins byte-for-byte compatibility of the stdlib BIP-39/SLIP-0010
    implementation (see crypto/mnemonic.py) for both key types, which
    bip-utils derived identically for Aptos (coin type 637).
    """

    VECTORS = [
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "m/44'/637'/0'/0'/0'",
            "0xcc92c0eaf80206d817f150e21917f797e49cf644a33ac514de3c316baa2f1bf5",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "m/44'/637'/0'/0'/1'",
            "0x3dc7bcd2c8186e6728c76e26a003ab18e8797332c964297bc7a8a4704a897646",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "m/44'/637'/1'/0'/0'",
            "0x4c6f5a6b687631dd52f32c97457e895fb57947b9b827c6697c11cd7b2a075c5b",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "m/44'/637'/2'/0'/5'",
            "0x1e0adae14a6f6a2a9e9e7688d528f9c241b68f65d3c20c2730f98b327568d5ea",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "m/44'/637'/0'/0'/0'",
            "0xec1587e9e79fa10bd0d2560233f571cd467a8b3d7de48691aa5e675c656f0e68",
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "m/44'/637'/0'/0'/10'",
            "0x304e34eae1dc4d7e44050cd0346de75ac766c9ab2a548499e946797fae68f17d",
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "m/44'/637'/0'/0'/0'",
            "0x4351297d2c3a216b55bf5922eb04b496194f6be825ef04ab20b61fa523044e63",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "m/44'/637'/0'/0'/0'",
            "0xf9575dc1f8c70253c68a15ef784f8c1cf5907644c5d22d2617f0153ed892e6af",
        ),
    ]

    @pytest.mark.parametrize("phrase,path,expected", VECTORS)
    def test_ed25519_vectors(self, phrase, path, expected):
        from aptos_sdk_v2.crypto.mnemonic import derive_ed25519_private_key

        assert derive_ed25519_private_key(phrase, path).hex() == expected

    @pytest.mark.parametrize("phrase,path,expected", VECTORS)
    def test_secp256k1_vectors(self, phrase, path, expected):
        from aptos_sdk_v2.crypto.mnemonic import derive_secp256k1_private_key

        assert derive_secp256k1_private_key(phrase, path).hex() == expected

    def test_invalid_checksum_rejected(self):
        # Same words as a valid phrase but with a broken checksum word.
        assert not validate_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        )


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

    def test_non_numeric_path_segment_raises_invalid_mnemonic(self):
        """Non-numeric path segments must raise InvalidMnemonicError, not ValueError."""
        from aptos_sdk_v2.crypto.mnemonic import derive_secp256k1_private_key

        phrase = generate_mnemonic()
        bad_path = "m/44'/637'/x'/0'/0'"
        with pytest.raises(InvalidMnemonicError, match="Non-numeric segment"):
            derive_ed25519_private_key(phrase, bad_path)
        with pytest.raises(InvalidMnemonicError, match="Non-numeric segment"):
            derive_secp256k1_private_key(phrase, bad_path)

    def test_extra_path_segments_rejected(self):
        """Paths with more or fewer than 6 segments must be rejected."""
        phrase = generate_mnemonic()
        with pytest.raises(InvalidMnemonicError):
            derive_ed25519_private_key(phrase, "m/44'/637'/0'/0'/0'/extra")

    def test_nonzero_change_index_rejected(self):
        """Non-zero change index must raise InvalidMnemonicError."""
        phrase = generate_mnemonic()
        with pytest.raises(InvalidMnemonicError, match="change index"):
            derive_ed25519_private_key(phrase, "m/44'/637'/0'/1'/0'")
