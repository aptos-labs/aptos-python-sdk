"""Unit tests for transactions — ported from v1 corpus-based hex tests."""

from aptos_sdk_v2.bcs import Deserializer, Serializer
from aptos_sdk_v2.crypto.authentication_key import AuthenticationKey
from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey
from aptos_sdk_v2.transactions.authenticator import Authenticator, MultiAgentAuthenticator
from aptos_sdk_v2.transactions.payload import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk_v2.transactions.raw_transaction import (
    FeePayerRawTransaction,
    MultiAgentRawTransaction,
    RawTransaction,
)
from aptos_sdk_v2.transactions.signed_transaction import SignedTransaction
from aptos_sdk_v2.types.account_address import AccountAddress
from aptos_sdk_v2.types.type_tag import StructTag, TypeTag


class TestEntryFunctionSignVerify:
    def test_sign_and_verify(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        account_address = AuthenticationKey.from_public_key(public_key).account_address()

        another_key = Ed25519PrivateKey.generate()
        recipient = AuthenticationKey.from_public_key(another_key.public_key()).account_address()

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [
                TransactionArgument(recipient, Serializer.struct),
                TransactionArgument(5000, Serializer.u64),
            ],
        )

        raw_txn = RawTransaction(
            account_address, 0, TransactionPayload(payload), 2000, 0, 18446744073709551615, 4
        )

        auth = raw_txn.sign(private_key)
        signed_txn = SignedTransaction(raw_txn, auth)
        assert signed_txn.verify()


class TestCorpus:
    """Validate against known hex corpus from v1 tests."""

    def test_entry_function_with_corpus(self):
        sender_key_input = "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f"
        receiver_key_input = "0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be"

        sender_private_key = Ed25519PrivateKey.from_str(sender_key_input)
        sender_public_key = sender_private_key.public_key()
        sender_address = AuthenticationKey.from_public_key(sender_public_key).account_address()

        receiver_private_key = Ed25519PrivateKey.from_str(receiver_key_input)
        receiver_public_key = receiver_private_key.public_key()
        receiver_address = AuthenticationKey.from_public_key(receiver_public_key).account_address()

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [
                TransactionArgument(receiver_address, Serializer.struct),
                TransactionArgument(5000, Serializer.u64),
            ],
        )

        raw_txn = RawTransaction(
            sender_address, 11, TransactionPayload(payload), 2000, 1, 1234567890, 4
        )

        auth = raw_txn.sign(sender_private_key)
        signed_txn = SignedTransaction(raw_txn, auth)
        assert signed_txn.verify()

        # Validate raw transaction hex
        expected_raw = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a6170746f735f636f696e094170746f73436f696e0002202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9088813000000000000d0070000000000000100000000000000d20296490000000004"

        ser = Serializer()
        raw_txn.serialize(ser)
        assert ser.output().hex() == expected_raw

        # Validate signed transaction hex
        expected_signed = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a6170746f735f636f696e094170746f73436f696e0002202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9088813000000000000d0070000000000000100000000000000d202964900000000040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040f25b74ec60a38a1ed780fd2bef6ddb6eb4356e3ab39276c9176cdf0fcae2ab37d79b626abb43d926e91595b66503a4a3c90acbae36a28d405e308f3537af720b"

        ser2 = Serializer()
        signed_txn.serialize(ser2)
        assert ser2.output().hex() == expected_signed

    def test_deserialize_raw_transaction(self):
        hex_input = "6b4003b51a1b33c398fe2b8fd3ca6a1d5dae0967350547813df937cdae2c36d400000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e736665720002206f20ce883cf1503cb4dc135e81a7a7b705486d342eaf182314e1a8299bc1586408e803000000000000a08601000000000064000000000000007a382e67000000009d"
        der = Deserializer(bytes.fromhex(hex_input))
        raw_txn = RawTransaction.deserialize(der)

        ser = Serializer()
        raw_txn.serialize(ser)
        assert ser.output().hex() == hex_input


class TestMultiAgentCorpus:
    def test_entry_function_multi_agent(self):
        sender_key_input = "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f"
        receiver_key_input = "0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be"

        sender_private_key = Ed25519PrivateKey.from_str(sender_key_input)
        sender_address = AuthenticationKey.from_public_key(
            sender_private_key.public_key()
        ).account_address()

        receiver_private_key = Ed25519PrivateKey.from_str(receiver_key_input)
        receiver_address = AuthenticationKey.from_public_key(
            receiver_private_key.public_key()
        ).account_address()

        payload = EntryFunction.natural(
            "0x3::token",
            "direct_transfer_script",
            [],
            [
                TransactionArgument(receiver_address, Serializer.struct),
                TransactionArgument("collection_name", Serializer.str),
                TransactionArgument("token_name", Serializer.str),
                TransactionArgument(1, Serializer.u64),
            ],
        )

        raw_txn = MultiAgentRawTransaction(
            RawTransaction(sender_address, 11, TransactionPayload(payload), 2000, 1, 1234567890, 4),
            [receiver_address],
        )

        sender_auth = raw_txn.sign(sender_private_key)
        receiver_auth = raw_txn.sign(receiver_private_key)

        authenticator = Authenticator(
            MultiAgentAuthenticator(sender_auth, [(receiver_address, receiver_auth)])
        )

        signed_txn = SignedTransaction(raw_txn.inner(), authenticator)
        assert signed_txn.verify()

        # Validate raw transaction hex
        expected_raw = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000305746f6b656e166469726563745f7472616e736665725f7363726970740004202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9100f636f6c6c656374696f6e5f6e616d650b0a746f6b656e5f6e616d65080100000000000000d0070000000000000100000000000000d20296490000000004"

        ser = Serializer()
        raw_txn.inner().serialize(ser)
        assert ser.output().hex() == expected_raw


class TestPayloadTypes:
    """Test Script, ScriptArgument, TransactionPayload, ModuleId, etc."""

    def test_module_id_eq(self):
        from aptos_sdk_v2.transactions.payload import ModuleId

        a = ModuleId.from_str("0x1::coin")
        b = ModuleId.from_str("0x1::coin")
        c = ModuleId.from_str("0x1::token")
        assert a == b
        assert a != c
        assert a != "not a module"
        assert str(a) == "0x1::coin"

    def test_module_id_serialize_round_trip(self):
        from aptos_sdk_v2.transactions.payload import ModuleId

        m = ModuleId.from_str("0x1::coin")
        ser = Serializer()
        m.serialize(ser)
        result = ModuleId.deserialize(Deserializer(ser.output()))
        assert m == result

    def test_entry_function_eq(self):
        a = EntryFunction.natural("0x1::coin", "transfer", [], [])
        b = EntryFunction.natural("0x1::coin", "transfer", [], [])
        c = EntryFunction.natural("0x1::coin", "mint", [], [])
        assert a == b
        assert a != c
        assert a != "x"

    def test_entry_function_str(self):
        ef = EntryFunction.natural("0x1::coin", "transfer", [], [])
        assert "transfer" in str(ef)

    def test_entry_function_serialize_round_trip(self):
        ef = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [
                TransactionArgument(AccountAddress.from_str("0x1"), Serializer.struct),
                TransactionArgument(1000, Serializer.u64),
            ],
        )
        ser = Serializer()
        ef.serialize(ser)
        result = EntryFunction.deserialize(Deserializer(ser.output()))
        assert ef == result

    def test_script_serialize_round_trip(self):
        from aptos_sdk_v2.transactions.payload import Script, ScriptArgument

        script = Script(
            b"\x00\x01\x02",
            [TypeTag(StructTag.from_str("0x1::coin::Coin"))],
            [ScriptArgument(ScriptArgument.U64, 42), ScriptArgument(ScriptArgument.BOOL, True)],
        )
        ser = Serializer()
        script.serialize(ser)
        result = Script.deserialize(Deserializer(ser.output()))
        assert script == result

    def test_script_eq(self):
        from aptos_sdk_v2.transactions.payload import Script

        a = Script(b"\x00", [], [])
        b = Script(b"\x00", [], [])
        c = Script(b"\x01", [], [])
        assert a == b
        assert a != c
        assert a != "x"

    def test_script_argument_all_variants(self):
        from aptos_sdk_v2.transactions.payload import ScriptArgument

        cases = [
            (ScriptArgument.U8, 255),
            (ScriptArgument.U16, 65535),
            (ScriptArgument.U32, 2**32 - 1),
            (ScriptArgument.U64, 2**64 - 1),
            (ScriptArgument.U128, 2**128 - 1),
            (ScriptArgument.U256, 2**256 - 1),
            (ScriptArgument.ADDRESS, AccountAddress.from_str("0x1")),
            (ScriptArgument.U8_VECTOR, b"\xab\xcd"),
            (ScriptArgument.BOOL, False),
        ]
        for variant, value in cases:
            arg = ScriptArgument(variant, value)
            ser = Serializer()
            arg.serialize(ser)
            result = ScriptArgument.deserialize(Deserializer(ser.output()))
            assert arg == result, f"Failed for variant {variant}"

    def test_script_argument_eq(self):
        from aptos_sdk_v2.transactions.payload import ScriptArgument

        a = ScriptArgument(ScriptArgument.U64, 42)
        b = ScriptArgument(ScriptArgument.U64, 42)
        assert a == b
        assert a != "x"

    def test_transaction_payload_script_round_trip(self):
        from aptos_sdk_v2.transactions.payload import Script

        script = Script(b"\x00\x01", [], [])
        tp = TransactionPayload(script)
        assert tp.variant == TransactionPayload.SCRIPT
        ser = Serializer()
        tp.serialize(ser)
        result = TransactionPayload.deserialize(Deserializer(ser.output()))
        assert tp == result

    def test_transaction_payload_entry_function_round_trip(self):
        ef = EntryFunction.natural("0x1::coin", "transfer", [], [])
        tp = TransactionPayload(ef)
        assert tp.variant == TransactionPayload.ENTRY_FUNCTION
        ser = Serializer()
        tp.serialize(ser)
        result = TransactionPayload.deserialize(Deserializer(ser.output()))
        assert tp == result

    def test_transaction_payload_eq(self):
        a = TransactionPayload(EntryFunction.natural("0x1::coin", "transfer", [], []))
        b = TransactionPayload(EntryFunction.natural("0x1::coin", "transfer", [], []))
        assert a == b
        assert a != "x"

    def test_transaction_payload_str(self):
        tp = TransactionPayload(EntryFunction.natural("0x1::coin", "transfer", [], []))
        assert "transfer" in str(tp)

    def test_transaction_payload_invalid_type(self):
        import pytest

        with pytest.raises(TypeError):
            TransactionPayload("bad")  # type: ignore[arg-type]


class TestSignedTransactionExtras:
    def test_signed_txn_bytes(self):
        key = Ed25519PrivateKey.generate()
        addr = AuthenticationKey.from_public_key(key.public_key()).account_address()
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999999, 4)
        auth = raw.sign(key)
        signed = SignedTransaction(raw, auth)
        data = signed.to_bytes()
        assert len(data) > 0

    def test_signed_txn_eq(self):
        key = Ed25519PrivateKey.generate()
        addr = AuthenticationKey.from_public_key(key.public_key()).account_address()
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999999, 4)
        auth = raw.sign(key)
        a = SignedTransaction(raw, auth)
        b = SignedTransaction(raw, auth)
        assert a == b
        assert a != "x"


class TestRawTransactionExtras:
    def test_raw_txn_eq(self):
        addr = AccountAddress.from_str("0x1")
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        a = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        b = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        assert a == b
        assert a != "x"

    def test_sign_simulated_ed25519(self):
        key = Ed25519PrivateKey.generate()
        addr = AuthenticationKey.from_public_key(key.public_key()).account_address()
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        auth = raw.sign_simulated(key.public_key())
        assert auth.variant == 0  # ED25519

    def test_sign_simulated_secp256k1(self):
        from aptos_sdk_v2.crypto.secp256k1 import Secp256k1PrivateKey

        key = Secp256k1PrivateKey.generate()
        addr = AccountAddress.from_str("0x1")
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        auth = raw.sign_simulated(key.public_key())
        assert auth.variant == 2  # SINGLE_KEY

    def test_sign_secp256k1(self):
        from aptos_sdk_v2.crypto.secp256k1 import Secp256k1PrivateKey

        key = Secp256k1PrivateKey.generate()
        addr = AccountAddress.from_str("0x1")
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        auth = raw.sign(key)
        assert auth.variant == 2  # SINGLE_KEY

    def test_fee_payer_sign_and_keyed(self):
        key = Ed25519PrivateKey.generate()
        addr = AuthenticationKey.from_public_key(key.public_key()).account_address()
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        fp = FeePayerRawTransaction(raw, [], addr)
        keyed = fp.keyed()
        assert len(keyed) > 0
        auth = fp.sign(key)
        assert auth is not None


class TestPayloadErrorBranches:
    def test_script_argument_invalid_deserialize_variant(self):
        import pytest

        from aptos_sdk_v2.errors import BcsDeserializationError
        from aptos_sdk_v2.transactions.payload import ScriptArgument

        ser = Serializer()
        ser.u8(99)
        with pytest.raises(BcsDeserializationError):
            ScriptArgument.deserialize(Deserializer(ser.output()))

    def test_script_argument_invalid_serialize_variant(self):
        import pytest

        from aptos_sdk_v2.errors import BcsSerializationError
        from aptos_sdk_v2.transactions.payload import ScriptArgument

        arg = ScriptArgument(99, None)
        ser = Serializer()
        with pytest.raises(BcsSerializationError):
            arg.serialize(ser)

    def test_transaction_payload_invalid_variant_deserialize(self):
        import pytest

        from aptos_sdk_v2.errors import BcsDeserializationError

        ser = Serializer()
        ser.uleb128(99)
        with pytest.raises(BcsDeserializationError):
            TransactionPayload.deserialize(Deserializer(ser.output()))

    def test_raw_transaction_verify(self):
        key = Ed25519PrivateKey.generate()
        addr = AuthenticationKey.from_public_key(key.public_key()).account_address()
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        sig = key.sign(raw.keyed())
        assert raw.verify(key.public_key(), sig)

    def test_multi_agent_deserialize_bad_tag(self):
        import pytest

        from aptos_sdk_v2.errors import BcsDeserializationError

        ser = Serializer()
        ser.u8(5)
        with pytest.raises(BcsDeserializationError):
            MultiAgentRawTransaction.deserialize(Deserializer(ser.output()))

    def test_fee_payer_deserialize_bad_tag(self):
        import pytest

        from aptos_sdk_v2.errors import BcsDeserializationError

        ser = Serializer()
        ser.u8(5)
        with pytest.raises(BcsDeserializationError):
            FeePayerRawTransaction.deserialize(Deserializer(ser.output()))

    def test_signed_transaction_deserialize_round_trip(self):
        key = Ed25519PrivateKey.generate()
        addr = AuthenticationKey.from_public_key(key.public_key()).account_address()
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        auth = raw.sign(key)
        signed = SignedTransaction(raw, auth)
        ser = Serializer()
        signed.serialize(ser)
        result = SignedTransaction.deserialize(Deserializer(ser.output()))
        assert signed == result

    def test_sign_simulated_unsupported_type(self):
        import pytest

        from aptos_sdk_v2.crypto.keys import PublicKey
        from aptos_sdk_v2.transactions.raw_transaction import _sign_simulated

        class FakeKey(PublicKey):
            def to_crypto_bytes(self):
                return b""

            def verify(self, d, s):
                return False

            def serialize(self, s):
                pass

            @staticmethod
            def deserialize(d):
                pass

        with pytest.raises(NotImplementedError):
            _sign_simulated(b"data", FakeKey())

    def test_multi_agent_deserialize_round_trip(self):
        """Test happy-path deserialization of MultiAgentRawTransaction."""
        addr = AccountAddress.from_str("0x1")
        sec_addr = AccountAddress.from_str("0x2")
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        ma = MultiAgentRawTransaction(raw, [sec_addr])
        ser = Serializer()
        ma.serialize(ser)
        result = MultiAgentRawTransaction.deserialize(Deserializer(ser.output()))
        assert result.raw_transaction == raw
        assert result.secondary_signers == [sec_addr]

    def test_fee_payer_inner(self):
        """Test FeePayerRawTransaction.inner() returns the RawTransaction."""
        addr = AccountAddress.from_str("0x1")
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        fp = FeePayerRawTransaction(raw, [], addr)
        assert fp.inner() == raw

    def test_multi_agent_inner(self):
        """Test MultiAgentRawTransaction.inner() returns the RawTransaction."""
        addr = AccountAddress.from_str("0x1")
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        ma = MultiAgentRawTransaction(raw, [])
        assert ma.inner() == raw


class TestSignedTransactionVerify:
    def test_verify_multi_agent(self):
        sender_key = Ed25519PrivateKey.generate()
        sender_addr = AuthenticationKey.from_public_key(sender_key.public_key()).account_address()
        secondary_key = Ed25519PrivateKey.generate()
        secondary_addr = AuthenticationKey.from_public_key(
            secondary_key.public_key()
        ).account_address()

        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(sender_addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        ma = MultiAgentRawTransaction(raw, [secondary_addr])

        sender_auth = ma.sign(sender_key)
        secondary_auth = ma.sign(secondary_key)

        authenticator = Authenticator(
            MultiAgentAuthenticator(sender_auth, [(secondary_addr, secondary_auth)])
        )
        signed = SignedTransaction(raw, authenticator)
        assert signed.verify()

    def test_verify_fee_payer(self):
        from aptos_sdk_v2.transactions.authenticator import FeePayerAuthenticator

        sender_key = Ed25519PrivateKey.generate()
        sender_addr = AuthenticationKey.from_public_key(sender_key.public_key()).account_address()
        payer_key = Ed25519PrivateKey.generate()
        payer_addr = AuthenticationKey.from_public_key(payer_key.public_key()).account_address()

        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(sender_addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        fp = FeePayerRawTransaction(raw, [], payer_addr)

        sender_auth = fp.sign(sender_key)
        payer_auth = fp.sign(payer_key)

        authenticator = Authenticator(
            FeePayerAuthenticator(sender_auth, [], (payer_addr, payer_auth))
        )
        signed = SignedTransaction(raw, authenticator)
        assert signed.verify()

    def test_single_sender_wrapping(self):
        """When AccountAuthenticator with SINGLE_KEY variant is passed, it wraps in SingleSender."""
        from aptos_sdk_v2.crypto.secp256k1 import Secp256k1PrivateKey

        key = Secp256k1PrivateKey.generate()
        addr = AccountAddress.from_str("0x1")
        payload = EntryFunction.natural("0x1::coin", "transfer", [], [])
        raw = RawTransaction(addr, 0, TransactionPayload(payload), 2000, 0, 999999, 4)
        auth = raw.sign(key)
        signed = SignedTransaction(raw, auth)
        assert signed.authenticator.variant == 4  # SINGLE_SENDER


class TestFeePayerDeserialization:
    def test_fee_payer_no_payer(self):
        hex_input = "01e5275b443b31ba82afc1780036e77b4bc11bb2d67cfbefd079abde7cf00a1c3b00000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e736665720002201152725822d847a4c4922f2d67af98ae76614b9137780cebcb9a14ea3646a63508e803000000000000a086010000000000640000000000000090392e67000000009d000000000000000000000000000000000000000000000000000000000000000000"
        der = Deserializer(bytes.fromhex(hex_input))
        txn = FeePayerRawTransaction.deserialize(der)
        assert txn.fee_payer is None

        ser = Serializer()
        txn.serialize(ser)
        assert ser.output().hex() == hex_input

    def test_fee_payer_with_payer(self):
        hex_input = "01a5ea85eada4d5cf6d0bdd1d1d348cab3812b2b76d1a4ce235ab5c42d3a530bc900000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220ffa66435120c841909d355aff22998ef838786baf699c1b96274cc542569333908e803000000000000a0860100000000006400000000000000b13b2e67000000009d00a5ea85eada4d5cf6d0bdd1d1d348cab3812b2b76d1a4ce235ab5c42d3a530bc9"
        der = Deserializer(bytes.fromhex(hex_input))
        txn = FeePayerRawTransaction.deserialize(der)
        assert txn.fee_payer == AccountAddress.from_str(
            "0xa5ea85eada4d5cf6d0bdd1d1d348cab3812b2b76d1a4ce235ab5c42d3a530bc9"
        )

        ser = Serializer()
        txn.serialize(ser)
        assert ser.output().hex() == hex_input
