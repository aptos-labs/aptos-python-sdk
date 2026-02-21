# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.mnemonic — BIP-39 mnemonic generation/validation and
SLIP-0010 key derivation.
"""

import pytest

from aptos_sdk.errors import InvalidInputError
from aptos_sdk.mnemonic import (
    DEFAULT_PATH,
    derive_key,
    generate_mnemonic,
    mnemonic_to_seed,
    validate_mnemonic,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestDefaultPath:
    def test_default_path_value(self):
        assert DEFAULT_PATH == "m/44'/637'/0'/0'/0'"


# ---------------------------------------------------------------------------
# generate_mnemonic
# ---------------------------------------------------------------------------


class TestGenerateMnemonic:
    def test_returns_12_words_by_default(self):
        try:
            phrase = generate_mnemonic()
            words = phrase.split()
            assert len(words) == 12
        except ImportError:
            pytest.skip("mnemonic package not installed")

    def test_returns_24_words(self):
        try:
            phrase = generate_mnemonic(24)
            words = phrase.split()
            assert len(words) == 24
        except ImportError:
            pytest.skip("mnemonic package not installed")

    def test_invalid_word_count_raises(self):
        try:
            with pytest.raises(InvalidInputError):
                generate_mnemonic(13)
        except ImportError:
            pytest.skip("mnemonic package not installed")

    def test_two_mnemonics_are_different(self):
        try:
            m1 = generate_mnemonic()
            m2 = generate_mnemonic()
            assert m1 != m2
        except ImportError:
            pytest.skip("mnemonic package not installed")


# ---------------------------------------------------------------------------
# validate_mnemonic
# ---------------------------------------------------------------------------


class TestValidateMnemonic:
    VALID_MNEMONIC = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    INVALID_MNEMONIC = "this is not a valid bip39 phrase at all yeah"

    def test_valid_mnemonic_returns_true(self):
        try:
            assert validate_mnemonic(self.VALID_MNEMONIC) is True
        except ImportError:
            pytest.skip("mnemonic package not installed")

    def test_invalid_mnemonic_returns_false(self):
        try:
            assert validate_mnemonic(self.INVALID_MNEMONIC) is False
        except ImportError:
            pytest.skip("mnemonic package not installed")

    def test_empty_string_returns_false(self):
        try:
            assert validate_mnemonic("") is False
        except ImportError:
            pytest.skip("mnemonic package not installed")


# ---------------------------------------------------------------------------
# mnemonic_to_seed
# ---------------------------------------------------------------------------


class TestMnemonicToSeed:
    MNEMONIC = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    def test_returns_64_bytes(self):
        seed = mnemonic_to_seed(self.MNEMONIC)
        assert isinstance(seed, bytes)
        assert len(seed) == 64

    def test_deterministic(self):
        seed1 = mnemonic_to_seed(self.MNEMONIC)
        seed2 = mnemonic_to_seed(self.MNEMONIC)
        assert seed1 == seed2

    def test_passphrase_changes_seed(self):
        seed_no_pass = mnemonic_to_seed(self.MNEMONIC)
        seed_with_pass = mnemonic_to_seed(self.MNEMONIC, passphrase="extra")
        assert seed_no_pass != seed_with_pass

    def test_different_mnemonics_produce_different_seeds(self):
        m1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        m2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        s1 = mnemonic_to_seed(m1)
        s2 = mnemonic_to_seed(m2)
        assert s1 != s2


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------


class TestDeriveKey:
    MNEMONIC = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    def _seed(self) -> bytes:
        return mnemonic_to_seed(self.MNEMONIC)

    def test_returns_32_bytes(self):
        key = derive_key(self._seed())
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_default_path_used(self):
        key = derive_key(self._seed())
        key2 = derive_key(self._seed(), DEFAULT_PATH)
        assert key == key2

    def test_deterministic_same_seed_and_path(self):
        seed = self._seed()
        k1 = derive_key(seed)
        k2 = derive_key(seed)
        assert k1 == k2

    def test_different_paths_produce_different_keys(self):
        seed = self._seed()
        k1 = derive_key(seed, "m/44'/637'/0'/0'/0'")
        k2 = derive_key(seed, "m/44'/637'/0'/0'/1'")
        assert k1 != k2

    def test_invalid_path_no_m_prefix_raises(self):
        seed = self._seed()
        with pytest.raises(InvalidInputError):
            derive_key(seed, "44'/637'/0'/0'/0'")

    def test_non_hardened_path_raises(self):
        seed = self._seed()
        with pytest.raises(InvalidInputError):
            derive_key(seed, "m/44'/637'/0")  # non-hardened segment

    def test_invalid_segment_index_raises(self):
        seed = self._seed()
        with pytest.raises(InvalidInputError):
            derive_key(seed, "m/44'/abc'")

    def test_custom_path(self):
        seed = self._seed()
        key = derive_key(seed, "m/44'/637'/1'/0'/0'")
        default_key = derive_key(seed)
        assert key != default_key
