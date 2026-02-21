# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for aptos_sdk.hashing — SHA3-256, SHA2-256, HashPrefix."""

import hashlib

from aptos_sdk.hashing import HashPrefix, sha2_256, sha3_256


class TestSha3256:
    def test_empty_input(self):
        result = sha3_256(b"")
        assert len(result) == 32
        assert result == hashlib.sha3_256(b"").digest()

    def test_known_input(self):
        result = sha3_256(b"hello")
        assert len(result) == 32
        assert result == hashlib.sha3_256(b"hello").digest()

    def test_deterministic(self):
        assert sha3_256(b"test") == sha3_256(b"test")

    def test_different_inputs(self):
        assert sha3_256(b"a") != sha3_256(b"b")

    def test_returns_bytes(self):
        assert isinstance(sha3_256(b"x"), bytes)


class TestSha2256:
    def test_empty_input(self):
        result = sha2_256(b"")
        assert len(result) == 32
        assert result == hashlib.sha256(b"").digest()

    def test_known_input(self):
        result = sha2_256(b"hello")
        assert result == hashlib.sha256(b"hello").digest()

    def test_deterministic(self):
        assert sha2_256(b"test") == sha2_256(b"test")


class TestHashPrefix:
    def test_raw_transaction_length(self):
        assert len(HashPrefix.RAW_TRANSACTION) == 32

    def test_raw_transaction_with_data_length(self):
        assert len(HashPrefix.RAW_TRANSACTION_WITH_DATA) == 32

    def test_raw_transaction_value(self):
        expected = sha3_256(b"APTOS::RawTransaction")
        assert HashPrefix.RAW_TRANSACTION == expected

    def test_raw_transaction_with_data_value(self):
        expected = sha3_256(b"APTOS::RawTransactionWithData")
        assert HashPrefix.RAW_TRANSACTION_WITH_DATA == expected

    def test_prefix_for_matches_constant(self):
        assert HashPrefix.prefix_for("RawTransaction") == HashPrefix.RAW_TRANSACTION

    def test_prefix_for_custom_domain(self):
        result = HashPrefix.prefix_for("MyDomain")
        assert len(result) == 32
        assert result == sha3_256(b"APTOS::MyDomain")

    def test_prefixes_differ(self):
        assert HashPrefix.RAW_TRANSACTION != HashPrefix.RAW_TRANSACTION_WITH_DATA

    def test_prefix_for_different_domains(self):
        assert HashPrefix.prefix_for("A") != HashPrefix.prefix_for("B")
