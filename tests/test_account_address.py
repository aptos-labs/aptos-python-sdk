# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for aptos_sdk.account_address — AccountAddress and AuthKeyScheme.
"""

import hashlib

import pytest

from aptos_sdk.account_address import AccountAddress, AuthKeyScheme
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.errors import InvalidAddressError, InvalidHexError, InvalidLengthError

# ---------------------------------------------------------------------------
# AuthKeyScheme
# ---------------------------------------------------------------------------


class TestAuthKeyScheme:
    def test_ed25519_scheme_byte(self):
        assert AuthKeyScheme.Ed25519 == b"\x00"

    def test_multi_ed25519_scheme_byte(self):
        assert AuthKeyScheme.MultiEd25519 == b"\x01"

    def test_single_key_scheme_byte(self):
        assert AuthKeyScheme.SingleKey == b"\x02"

    def test_multi_key_scheme_byte(self):
        assert AuthKeyScheme.MultiKey == b"\x03"

    def test_derive_resource_account_byte(self):
        assert AuthKeyScheme.DeriveResourceAccountAddress == b"\xFF"

    def test_derive_named_object_byte(self):
        assert AuthKeyScheme.DeriveObjectAddressFromSeed == b"\xFE"

    def test_derive_guid_object_byte(self):
        assert AuthKeyScheme.DeriveObjectAddressFromGuid == b"\xFD"


# ---------------------------------------------------------------------------
# AccountAddress construction
# ---------------------------------------------------------------------------


class TestAccountAddressConstruction:
    def test_init_accepts_32_bytes(self):
        data = bytes(range(32))
        addr = AccountAddress(data)
        assert addr.data == data

    def test_init_rejects_short_bytes(self):
        with pytest.raises(InvalidLengthError):
            AccountAddress(b"\x00" * 31)

    def test_init_rejects_long_bytes(self):
        with pytest.raises(InvalidLengthError):
            AccountAddress(b"\x00" * 33)

    def test_init_rejects_empty(self):
        with pytest.raises(InvalidLengthError):
            AccountAddress(b"")

    def test_from_bytes_factory(self):
        data = b"\xab" * 32
        addr = AccountAddress.from_bytes(data)
        assert addr.data == data

    def test_from_bytes_wrong_length_raises(self):
        with pytest.raises(InvalidLengthError):
            AccountAddress.from_bytes(b"\x00" * 10)


# ---------------------------------------------------------------------------
# from_hex
# ---------------------------------------------------------------------------


class TestFromHex:
    def test_full_hex_without_prefix(self):
        hex_str = "ab" * 32
        addr = AccountAddress.from_hex(hex_str)
        assert addr.data == bytes.fromhex(hex_str)

    def test_full_hex_with_0x_prefix(self):
        hex_str = "ab" * 32
        addr = AccountAddress.from_hex("0x" + hex_str)
        assert addr.data == bytes.fromhex(hex_str)

    def test_short_hex_is_left_padded(self):
        addr = AccountAddress.from_hex("0x1")
        assert addr.data == b"\x00" * 31 + b"\x01"

    def test_too_long_raises(self):
        with pytest.raises(InvalidHexError):
            AccountAddress.from_hex("0x" + "a" * 65)

    def test_empty_string_raises(self):
        with pytest.raises(InvalidHexError):
            AccountAddress.from_hex("")

    def test_only_prefix_raises(self):
        with pytest.raises(InvalidHexError):
            AccountAddress.from_hex("0x")

    def test_invalid_hex_chars_raises(self):
        with pytest.raises(InvalidHexError):
            AccountAddress.from_hex("0xGGGG")

    def test_uppercase_prefix(self):
        addr = AccountAddress.from_hex("0X01")
        assert addr.data == b"\x00" * 31 + b"\x01"

    def test_case_insensitive(self):
        addr_lower = AccountAddress.from_hex("0x" + "ab" * 32)
        addr_upper = AccountAddress.from_hex("0x" + "AB" * 32)
        assert addr_lower == addr_upper


# ---------------------------------------------------------------------------
# from_str (strict AIP-40)
# ---------------------------------------------------------------------------


class TestFromStr:
    def test_long_form_accepted(self):
        hex_body = "a" * 64
        addr = AccountAddress.from_str("0x" + hex_body)
        assert addr.data == bytes.fromhex(hex_body)

    def test_short_form_special_address(self):
        for i in range(16):
            addr = AccountAddress.from_str(f"0x{i:x}")
            assert addr.data == b"\x00" * 31 + bytes([i])

    def test_missing_prefix_raises(self):
        with pytest.raises(InvalidAddressError):
            AccountAddress.from_str("a" * 64)

    def test_padded_short_form_raises(self):
        # "0x01" is two chars, not one; padded short form is not allowed
        with pytest.raises(InvalidAddressError):
            AccountAddress.from_str("0x01")

    def test_non_special_address_short_form_raises(self):
        # A non-special address must use LONG form (64 chars after 0x)
        with pytest.raises(InvalidAddressError):
            AccountAddress.from_str(
                "0x10"
            )  # "10" in hex is 16 — not special and not 64 chars

    def test_long_form_with_all_zeros_ok(self):
        addr = AccountAddress.from_str("0x" + "0" * 64)
        assert addr == AccountAddress.ZERO


# ---------------------------------------------------------------------------
# from_str_relaxed
# ---------------------------------------------------------------------------


class TestFromStrRelaxed:
    def test_accepts_padded_short_form(self):
        addr = AccountAddress.from_str_relaxed("0x0f")
        assert addr.data == b"\x00" * 31 + b"\x0f"

    def test_accepts_long_form(self):
        hex_body = "cd" * 32
        addr = AccountAddress.from_str_relaxed("0x" + hex_body)
        assert addr.data == bytes.fromhex(hex_body)

    def test_accepts_without_prefix(self):
        hex_body = "cd" * 32
        addr = AccountAddress.from_str_relaxed(hex_body)
        assert addr.data == bytes.fromhex(hex_body)


# ---------------------------------------------------------------------------
# is_special
# ---------------------------------------------------------------------------


class TestIsSpecial:
    def test_zero_is_special(self):
        assert AccountAddress.ZERO.is_special()

    def test_one_is_special(self):
        assert AccountAddress.ONE.is_special()

    def test_0xf_is_special(self):
        addr = AccountAddress.from_hex("0xf")
        assert addr.is_special()

    def test_0x10_is_not_special(self):
        addr = AccountAddress.from_hex("0x10")
        assert not addr.is_special()

    def test_random_address_not_special(self):
        addr = AccountAddress(b"\xab" * 32)
        assert not addr.is_special()

    def test_three_is_special(self):
        assert AccountAddress.THREE.is_special()

    def test_four_is_special(self):
        assert AccountAddress.FOUR.is_special()


# ---------------------------------------------------------------------------
# String representation
# ---------------------------------------------------------------------------


class TestStrRepresentation:
    def test_special_address_short_form(self):
        assert str(AccountAddress.ZERO) == "0x0"
        assert str(AccountAddress.ONE) == "0x1"

    def test_0xf_short_form(self):
        addr = AccountAddress.from_hex("0xf")
        assert str(addr) == "0xf"

    def test_non_special_long_form(self):
        data = bytes(range(32))
        addr = AccountAddress(data)
        assert str(addr) == "0x" + data.hex()
        assert len(str(addr)) == 2 + 64  # "0x" + 64 hex chars

    def test_to_hex_always_long(self):
        # Even special addresses should have 66 chars in to_hex()
        assert len(AccountAddress.ZERO.to_hex()) == 66
        assert AccountAddress.ZERO.to_hex() == "0x" + "0" * 64

    def test_to_short_string(self):
        addr = AccountAddress.from_hex("0xabc")
        short = addr.to_short_string()
        assert short.startswith("0x")
        assert short == "0xabc"

    def test_repr(self):
        r = repr(AccountAddress.ONE)
        assert "AccountAddress" in r
        assert "0x1" in r


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_zero_constant(self):
        assert AccountAddress.ZERO.data == b"\x00" * 32
        assert str(AccountAddress.ZERO) == "0x0"

    def test_one_constant(self):
        assert AccountAddress.ONE.data == b"\x00" * 31 + b"\x01"
        assert str(AccountAddress.ONE) == "0x1"

    def test_three_constant(self):
        assert AccountAddress.THREE.data == b"\x00" * 31 + b"\x03"
        assert str(AccountAddress.THREE) == "0x3"

    def test_four_constant(self):
        assert AccountAddress.FOUR.data == b"\x00" * 31 + b"\x04"
        assert str(AccountAddress.FOUR) == "0x4"

    def test_length_constant(self):
        assert AccountAddress.LENGTH == 32


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_cannot_set_data(self):
        addr = AccountAddress.ZERO
        with pytest.raises(AttributeError):
            addr.data = b"\x00" * 32  # type: ignore[misc]

    def test_cannot_set_arbitrary_attr(self):
        addr = AccountAddress.ZERO
        with pytest.raises(AttributeError):
            addr.foo = "bar"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Equality and hashing
# ---------------------------------------------------------------------------


class TestEqualityAndHashing:
    def test_equal_addresses(self):
        a = AccountAddress.from_hex("0x1")
        b = AccountAddress.from_hex("0x1")
        assert a == b

    def test_different_addresses_not_equal(self):
        assert AccountAddress.ZERO != AccountAddress.ONE

    def test_not_equal_to_non_address(self):
        result = AccountAddress.ZERO.__eq__("not an address")
        assert result is NotImplemented

    def test_hashable(self):
        a = AccountAddress.from_hex("0x1")
        b = AccountAddress.from_hex("0x1")
        assert hash(a) == hash(b)

    def test_usable_in_set(self):
        s = {AccountAddress.ZERO, AccountAddress.ONE, AccountAddress.ZERO}
        assert len(s) == 2

    def test_usable_as_dict_key(self):
        d = {AccountAddress.ONE: "aptos"}
        assert d[AccountAddress.ONE] == "aptos"


# ---------------------------------------------------------------------------
# BCS round-trip
# ---------------------------------------------------------------------------


class TestBcsRoundTrip:
    def test_serialize_deserialize(self):
        original = AccountAddress(bytes(range(32)))
        ser = Serializer()
        original.serialize(ser)
        der = Deserializer(ser.output())
        restored = AccountAddress.deserialize(der)
        assert restored == original

    def test_zero_bcs_round_trip(self):
        ser = Serializer()
        AccountAddress.ZERO.serialize(ser)
        der = Deserializer(ser.output())
        assert AccountAddress.deserialize(der) == AccountAddress.ZERO

    def test_serialized_length_is_32(self):
        ser = Serializer()
        AccountAddress.ONE.serialize(ser)
        assert len(ser.output()) == 32


# ---------------------------------------------------------------------------
# from_key (address derivation)
# ---------------------------------------------------------------------------


class TestFromKey:
    def test_from_ed25519_key(self):
        from aptos_sdk.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        addr = AccountAddress.from_key(pub)
        assert isinstance(addr, AccountAddress)
        assert len(addr.data) == 32

    def test_from_ed25519_key_deterministic(self):
        from aptos_sdk.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        addr1 = AccountAddress.from_key(pub)
        addr2 = AccountAddress.from_key(pub)
        assert addr1 == addr2

    def test_from_multi_ed25519_key(self):
        from aptos_sdk.ed25519 import Ed25519PrivateKey, MultiEd25519PublicKey

        keys = [Ed25519PrivateKey.generate().public_key() for _ in range(2)]
        multi_key = MultiEd25519PublicKey(keys, 2)
        addr = AccountAddress.from_key(multi_key)
        assert isinstance(addr, AccountAddress)

    def test_from_any_public_key(self):
        from aptos_sdk.crypto_wrapper import AnyPublicKey
        from aptos_sdk.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        any_key = AnyPublicKey(priv.public_key())
        addr = AccountAddress.from_key(any_key)
        assert isinstance(addr, AccountAddress)

    def test_from_multi_key_public_key(self):
        from aptos_sdk.crypto_wrapper import MultiKeyPublicKey
        from aptos_sdk.ed25519 import Ed25519PrivateKey

        keys = [Ed25519PrivateKey.generate().public_key() for _ in range(2)]
        multi = MultiKeyPublicKey(keys, 2)
        addr = AccountAddress.from_key(multi)
        assert isinstance(addr, AccountAddress)

    def test_from_unsupported_key_raises(self):
        class FakeKey:
            def to_crypto_bytes(self):
                return b"\x00" * 32

        with pytest.raises(InvalidAddressError):
            AccountAddress.from_key(FakeKey())

    def test_auth_key_derivation_matches_manual(self):
        from aptos_sdk.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        expected = hashlib.sha3_256(
            pub.to_crypto_bytes() + AuthKeyScheme.Ed25519
        ).digest()
        addr = AccountAddress.from_key(pub)
        assert addr.data == expected


# ---------------------------------------------------------------------------
# Derived address constructors
# ---------------------------------------------------------------------------


class TestDerivedAddressConstructors:
    def test_for_resource_account(self):
        creator = AccountAddress.ONE
        seed = b"my_seed"
        addr = AccountAddress.for_resource_account(creator, seed)
        assert isinstance(addr, AccountAddress)

        # Verify manual derivation matches
        hasher = hashlib.sha3_256()
        hasher.update(creator.data)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DeriveResourceAccountAddress)
        assert addr.data == hasher.digest()

    def test_for_named_object(self):
        creator = AccountAddress.ONE
        seed = b"object_seed"
        addr = AccountAddress.for_named_object(creator, seed)
        assert isinstance(addr, AccountAddress)

    def test_for_named_collection(self):
        creator = AccountAddress.ONE
        addr = AccountAddress.for_named_collection(creator, "MyCollection")
        expected = AccountAddress.for_named_object(creator, "MyCollection".encode())
        assert addr == expected

    def test_for_named_token(self):
        creator = AccountAddress.ONE
        addr = AccountAddress.for_named_token(creator, "Collection", "Token")
        seed = "Collection".encode() + b"::" + "Token".encode()
        expected = AccountAddress.for_named_object(creator, seed)
        assert addr == expected

    def test_for_guid_object(self):
        creator = AccountAddress.ONE
        addr = AccountAddress.for_guid_object(creator, 0)
        assert isinstance(addr, AccountAddress)
