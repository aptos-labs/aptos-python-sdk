"""Unit tests for AccountAddress — ported from v1 AIP-40 test vectors."""

import pytest

from aptos_sdk_v2.types.account_address import AccountAddress


# --- Test data ---

ADDR_ZERO_LONG = "0x0000000000000000000000000000000000000000000000000000000000000000"
ADDR_ZERO_SHORT = "0x0"
ADDR_F_LONG = "0x000000000000000000000000000000000000000000000000000000000000000f"
ADDR_F_SHORT = "0xf"
ADDR_TEN_LONG = "0x0000000000000000000000000000000000000000000000000000000000000010"
ADDR_OTHER = "0xca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0"


class TestFromStrRelaxed:
    def test_zero_all_formats(self):
        assert str(AccountAddress.from_str_relaxed(ADDR_ZERO_LONG)) == ADDR_ZERO_SHORT
        assert str(AccountAddress.from_str_relaxed("0")) == ADDR_ZERO_SHORT
        assert str(AccountAddress.from_str_relaxed("0x0")) == ADDR_ZERO_SHORT
        long_no_prefix = ADDR_ZERO_LONG[2:]
        assert str(AccountAddress.from_str_relaxed(long_no_prefix)) == ADDR_ZERO_SHORT

    def test_f_all_formats(self):
        assert str(AccountAddress.from_str_relaxed(ADDR_F_LONG)) == ADDR_F_SHORT
        assert str(AccountAddress.from_str_relaxed("f")) == ADDR_F_SHORT
        assert str(AccountAddress.from_str_relaxed("0xf")) == ADDR_F_SHORT
        assert str(AccountAddress.from_str_relaxed("0x0f")) == ADDR_F_SHORT

    def test_ten_all_formats(self):
        assert str(AccountAddress.from_str_relaxed(ADDR_TEN_LONG)) == ADDR_TEN_LONG
        assert str(AccountAddress.from_str_relaxed("10")) == ADDR_TEN_LONG
        assert str(AccountAddress.from_str_relaxed("0x10")) == ADDR_TEN_LONG

    def test_other_address(self):
        assert str(AccountAddress.from_str_relaxed(ADDR_OTHER)) == ADDR_OTHER
        assert str(AccountAddress.from_str_relaxed(ADDR_OTHER[2:])) == ADDR_OTHER


class TestFromStr:
    def test_zero_long(self):
        assert str(AccountAddress.from_str(ADDR_ZERO_LONG)) == ADDR_ZERO_SHORT

    def test_zero_short(self):
        assert str(AccountAddress.from_str(ADDR_ZERO_SHORT)) == ADDR_ZERO_SHORT

    def test_zero_no_prefix_fails(self):
        with pytest.raises(Exception):
            AccountAddress.from_str("0")

    def test_f_long(self):
        assert str(AccountAddress.from_str(ADDR_F_LONG)) == ADDR_F_SHORT

    def test_f_short(self):
        assert str(AccountAddress.from_str(ADDR_F_SHORT)) == ADDR_F_SHORT

    def test_padded_short_fails(self):
        with pytest.raises(Exception):
            AccountAddress.from_str("0x0f")

    def test_ten_long(self):
        assert str(AccountAddress.from_str(ADDR_TEN_LONG)) == ADDR_TEN_LONG

    def test_ten_short_fails(self):
        with pytest.raises(Exception):
            AccountAddress.from_str("0x10")

    def test_other_long(self):
        assert str(AccountAddress.from_str(ADDR_OTHER)) == ADDR_OTHER

    def test_other_no_prefix_fails(self):
        with pytest.raises(Exception):
            AccountAddress.from_str(ADDR_OTHER[2:])


class TestIsSpecial:
    def test_zero_is_special(self):
        assert AccountAddress.from_str_relaxed("0x0").is_special()

    def test_f_is_special(self):
        assert AccountAddress.from_str_relaxed("0xf").is_special()

    def test_ten_is_not_special(self):
        assert not AccountAddress.from_str_relaxed("0x10").is_special()


class TestBcsSerialization:
    def test_round_trip(self):
        from aptos_sdk_v2.bcs import Deserializer, Serializer

        addr = AccountAddress.from_str(ADDR_OTHER)
        ser = Serializer()
        addr.serialize(ser)
        der = Deserializer(ser.output())
        result = AccountAddress.deserialize(der)
        assert addr == result


class TestDerivedAddresses:
    def test_resource_account(self):
        base = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "ee89f8c763c27f9d942d496c1a0dcf32d5eacfe78416f9486b8db66155b163b0"
        )
        assert AccountAddress.for_resource_account(base, b"\x0b\x00\x0b") == expected

    def test_named_object(self):
        base = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "f417184602a828a3819edf5e36285ebef5e4db1ba36270be580d6fd2d7bcc321"
        )
        assert AccountAddress.for_named_object(base, b"bob's collection") == expected

    def test_named_collection(self):
        base = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "f417184602a828a3819edf5e36285ebef5e4db1ba36270be580d6fd2d7bcc321"
        )
        assert AccountAddress.for_named_collection(base, "bob's collection") == expected

    def test_named_token(self):
        base = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "e20d1f22a5400ba7be0f515b7cbd00edc42dbcc31acc01e31128b2b5ddb3c56e"
        )
        assert AccountAddress.for_named_token(base, "bob's collection", "bob's token") == expected


class TestEquality:
    def test_equal(self):
        a = AccountAddress.from_str_relaxed("0x1")
        b = AccountAddress.from_str_relaxed("0x1")
        assert a == b

    def test_frozen_hashable(self):
        a = AccountAddress.from_str_relaxed("0x1")
        d = {a: "value"}
        assert d[a] == "value"

    def test_to_standard_string_nonspecial(self):
        value = "0x00000000000000000000000000000000000000000000000000000000000000a0"
        assert str(AccountAddress.from_str_relaxed(value)) == value

    def test_leading_zeros_preserved(self):
        value = "0f00000000000000000000000000000000000000000000000000000000000000"
        assert str(AccountAddress.from_str_relaxed(value)) == f"0x{value}"


class TestGuidObject:
    def test_guid_object_derivation(self):
        creator = AccountAddress.from_str_relaxed("0xb0b")
        derived = AccountAddress.for_guid_object(creator, 42)
        assert isinstance(derived, AccountAddress)
        assert len(derived.address) == 32


class TestErrorPaths:
    def test_invalid_length_raises(self):
        from aptos_sdk_v2.errors import InvalidAddressError

        with pytest.raises(InvalidAddressError):
            AccountAddress(b"\x00" * 31)

    def test_from_str_relaxed_empty_raises(self):
        from aptos_sdk_v2.errors import InvalidAddressError

        with pytest.raises(InvalidAddressError):
            AccountAddress.from_str_relaxed("0x")

    def test_from_str_relaxed_too_long_raises(self):
        from aptos_sdk_v2.errors import InvalidAddressError

        with pytest.raises(InvalidAddressError):
            AccountAddress.from_str_relaxed("0x" + "a" * 65)

    def test_repr(self):
        addr = AccountAddress.from_str("0x1")
        assert repr(addr) == "0x1"
