# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Extra unit tests for the legacy v1 SDK modules.

These tests target previously-uncovered code paths so that ``make test-coverage``
produces a more accurate picture of what's actually exercised. They are placed
in a ``*_test.py`` file (matching the coverage ``omit`` glob in
``pyproject.toml``) so the test code itself does not inflate coverage numbers.

Network-dependent paths are exercised via an ``httpx.MockTransport`` rather
than real devnet calls, keeping ``make test`` hermetic and fast.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from typing import Callable
from unittest import mock

import httpx

from . import asymmetric_crypto_wrapper, ed25519, secp256k1_ecdsa
from .account import Account
from .account_address import AccountAddress
from .aptos_token_client import (
    AptosTokenClient,
    Collection,
    InvalidPropertyType,
    Object,
    Property,
    PropertyMap,
    ReadObject,
    Royalty,
    Token,
)
from .aptos_tokenv1_client import AptosTokenV1Client
from .async_client import (
    AccountNotFound,
    ApiError,
    ClientConfig,
    FaucetClient,
    IndexerClient,
    IndexerError,
    ResourceNotFound,
    RestClient,
    TransactionFailed,
    TransactionTimeout,
)
from .authenticator import (
    Authenticator,
    Ed25519Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
    SingleSenderAuthenticator,
)
from .bcs import Deserializer, Serializer
from .cli import key_value
from .errors import InvalidTypeError
from .package_publisher import (
    MAX_TRANSACTION_SIZE,
    OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR,
    PackagePublisher,
    PublishMode,
)
from .transactions import (
    EntryFunction,
    ModuleId,
    RawTransaction,
    Script,
    ScriptArgument,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from .type_tag import (
    AccountAddressTag,
    BoolTag,
    StructTag,
    TypeTag,
    U8Tag,
    U16Tag,
    U32Tag,
    U64Tag,
    U128Tag,
    U256Tag,
)


def _build_rest_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    base_url: str = "http://mock.invalid/v1",
) -> RestClient:
    """Construct a RestClient whose underlying httpx.AsyncClient is mocked."""
    client = RestClient(base_url, ClientConfig(http2=False, transaction_wait_in_seconds=2))
    _run(client.client.aclose())
    transport = httpx.MockTransport(handler)
    client.client = httpx.AsyncClient(base_url="", transport=transport)
    return client


def _run(coro):
    """Run a coroutine in a fresh, properly-closed event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


SAMPLE_ADDR = "0x0000000000000000000000000000000000000000000000000000000000000a11"


class ScriptArgumentTests(unittest.TestCase):
    def test_all_variants_round_trip(self):
        addr = AccountAddress.from_str_relaxed("0x42")
        cases = [
            ScriptArgument(ScriptArgument.U8, 17),
            ScriptArgument(ScriptArgument.U16, 17000),
            ScriptArgument(ScriptArgument.U32, 1_700_000),
            ScriptArgument(ScriptArgument.U64, 17_000_000_000),
            ScriptArgument(ScriptArgument.U128, 1 << 100),
            ScriptArgument(ScriptArgument.U256, 1 << 200),
            ScriptArgument(ScriptArgument.ADDRESS, addr),
            ScriptArgument(ScriptArgument.U8_VECTOR, b"\x01\x02\x03"),
            ScriptArgument(ScriptArgument.BOOL, True),
        ]
        for arg in cases:
            ser = Serializer()
            arg.serialize(ser)
            de = Deserializer(ser.output())
            round = ScriptArgument.deserialize(de)
            self.assertEqual(arg, round)
            self.assertIn(str(arg.variant), str(arg))

    def test_invalid_variant_raises(self):
        with self.assertRaises(InvalidTypeError):
            ScriptArgument(99, 0)
        with self.assertRaises(InvalidTypeError):
            ScriptArgument(-1, 0)


class ScriptRoundTripTests(unittest.TestCase):
    def test_script_serializes_and_compares(self):
        s1 = Script(b"\xde\xad\xbe\xef", [], [ScriptArgument(ScriptArgument.U64, 1)])
        ser = Serializer()
        s1.serialize(ser)
        s2 = Script.deserialize(Deserializer(ser.output()))
        self.assertEqual(s1, s2)
        self.assertNotEqual(s1, "not a script")
        # Script has __str__ that includes ty_args / args representations.
        self.assertIn("<", str(s1))

    def test_script_payload_round_trip(self):
        payload = TransactionPayload(Script(b"\x00", [], []))
        ser = Serializer()
        payload.serialize(ser)
        out = TransactionPayload.deserialize(Deserializer(ser.output()))
        self.assertEqual(payload, out)
        self.assertEqual(payload.variant, TransactionPayload.SCRIPT)


class TransactionPayloadInvalidTypeTests(unittest.TestCase):
    def test_invalid_payload_type_raises(self):
        with self.assertRaises(InvalidTypeError):
            TransactionPayload(object())

    def test_payload_eq_other_type(self):
        p = TransactionPayload(Script(b"", [], []))
        self.assertNotEqual(p, "not a payload")


class ModuleIdTests(unittest.TestCase):
    def test_module_id_round_trip(self):
        mid = ModuleId.from_str("0x1::aptos_account")
        self.assertEqual(str(mid), "0x1::aptos_account")
        self.assertEqual(mid, ModuleId.from_str("0x1::aptos_account"))
        self.assertNotEqual(mid, "x")
        ser = Serializer()
        mid.serialize(ser)
        out = ModuleId.deserialize(Deserializer(ser.output()))
        self.assertEqual(mid, out)


class TypeTagTests(unittest.TestCase):
    def test_primitive_tag_round_trips(self):
        cases = [
            TypeTag(BoolTag(True)),
            TypeTag(U8Tag(7)),
            TypeTag(U16Tag(7)),
            TypeTag(U32Tag(7)),
            TypeTag(U64Tag(7)),
            TypeTag(U128Tag(7)),
            TypeTag(U256Tag(7)),
            TypeTag(AccountAddressTag(AccountAddress.from_str_relaxed("0x1"))),
        ]
        for tag in cases:
            ser = Serializer()
            tag.serialize(ser)
            out = TypeTag.deserialize(Deserializer(ser.output()))
            self.assertEqual(tag, out)
            self.assertEqual(repr(tag), str(tag))
            self.assertNotEqual(tag, "not a tag")
            self.assertNotEqual(tag.value, "not equal")

    def test_struct_tag_with_type_args(self):
        tag = StructTag.from_str("0x1::coin::Coin<0x1::aptos_coin::AptosCoin>")
        self.assertEqual(
            str(tag),
            "0x1::coin::Coin<0x1::aptos_coin::AptosCoin>",
        )
        round = StructTag.from_bytes(tag.to_bytes())
        self.assertEqual(tag, round)
        self.assertNotEqual(tag, "x")

    def test_signer_and_vector_unimplemented(self):
        ser = Serializer()
        ser.uleb128(TypeTag.SIGNER)
        with self.assertRaises(NotImplementedError):
            TypeTag.deserialize(Deserializer(ser.output()))
        ser = Serializer()
        ser.uleb128(TypeTag.VECTOR)
        with self.assertRaises(NotImplementedError):
            TypeTag.deserialize(Deserializer(ser.output()))


class AsymmetricCryptoWrapperTests(unittest.TestCase):
    def test_ed25519_round_trip(self):
        sk = ed25519.PrivateKey.random()
        pk = asymmetric_crypto_wrapper.PublicKey(sk.public_key())
        sig = asymmetric_crypto_wrapper.Signature(sk.sign(b"hello"))
        self.assertTrue(pk.verify(b"hello", sig))

        ser = Serializer()
        pk.serialize(ser)
        out = asymmetric_crypto_wrapper.PublicKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(out.variant, asymmetric_crypto_wrapper.PublicKey.ED25519)

        ser = Serializer()
        sig.serialize(ser)
        sig_out = asymmetric_crypto_wrapper.Signature.deserialize(Deserializer(ser.output()))
        self.assertEqual(sig_out.variant, asymmetric_crypto_wrapper.Signature.ED25519)

    def test_secp256k1_round_trip(self):
        sk = secp256k1_ecdsa.PrivateKey.random()
        pk = asymmetric_crypto_wrapper.PublicKey(sk.public_key())
        sig = asymmetric_crypto_wrapper.Signature(sk.sign(b"hello"))
        self.assertTrue(pk.verify(b"hello", sig))

        ser = Serializer()
        pk.serialize(ser)
        out = asymmetric_crypto_wrapper.PublicKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(out.variant, asymmetric_crypto_wrapper.PublicKey.SECP256K1_ECDSA)
        # The deserialized wrapped public key should match the input bytes.
        self.assertEqual(out.public_key.to_crypto_bytes(), sk.public_key().to_crypto_bytes())

    def test_invalid_variant_raises(self):
        with self.assertRaises(NotImplementedError):
            asymmetric_crypto_wrapper.PublicKey("not a key")  # type: ignore[arg-type]
        with self.assertRaises(NotImplementedError):
            asymmetric_crypto_wrapper.Signature("not a sig")  # type: ignore[arg-type]

    def test_invalid_deserialized_variant(self):
        ser = Serializer()
        ser.uleb128(99)
        ser.u8(0)
        with self.assertRaises(InvalidTypeError):
            asymmetric_crypto_wrapper.PublicKey.deserialize(Deserializer(ser.output()))
        ser = Serializer()
        ser.uleb128(99)
        ser.u8(0)
        with self.assertRaises(InvalidTypeError):
            asymmetric_crypto_wrapper.Signature.deserialize(Deserializer(ser.output()))

    def test_multi_public_key_validation(self):
        sk = ed25519.PrivateKey.random()
        pk = asymmetric_crypto_wrapper.PublicKey(sk.public_key())
        with self.assertRaises(ValueError):
            asymmetric_crypto_wrapper.MultiPublicKey([pk], 1)
        with self.assertRaises(ValueError):
            asymmetric_crypto_wrapper.MultiPublicKey([pk] * 33, 1)
        with self.assertRaises(ValueError):
            asymmetric_crypto_wrapper.MultiPublicKey([pk, pk], 0)
        ok = asymmetric_crypto_wrapper.MultiPublicKey([pk, pk], 2)
        self.assertEqual(ok.threshold, 2)
        self.assertEqual(str(ok), "2-of-2 Multi key")

    def test_multi_signature_round_trip(self):
        sk = ed25519.PrivateKey.random()
        sig = asymmetric_crypto_wrapper.Signature(sk.sign(b"x"))
        ms = asymmetric_crypto_wrapper.MultiSignature([(0, sig), (3, sig)])
        ser = Serializer()
        ms.serialize(ser)
        out = asymmetric_crypto_wrapper.MultiSignature.deserialize(Deserializer(ser.output()))
        self.assertEqual([i for i, _ in ms.signatures], [i for i, _ in out.signatures])
        # Re-serializing the deserialized form must produce the original bytes.
        ser2 = Serializer()
        out.serialize(ser2)
        self.assertEqual(ser.output(), ser2.output())
        self.assertNotEqual(ms, "x")
        with self.assertRaises(ValueError):
            asymmetric_crypto_wrapper.MultiSignature([(99, sig)])


class IndexerClientTests(unittest.TestCase):
    def test_query_handles_errors_field(self):
        client = IndexerClient("http://mock.invalid/graphql")

        async def fake_query(query, variables):
            return {"errors": [{"message": "boom"}]}

        client.client.execute_async = fake_query  # type: ignore[assignment]
        with self.assertRaises(IndexerError):
            _run(client.query("{x}", {}))

    def test_query_wraps_transport_error(self):
        import aiohttp

        client = IndexerClient("http://mock.invalid/graphql", bearer_token="t")

        async def fake_query(query, variables):
            # Simulate the real failure mode: indexer returns HTML on rate-limit
            # and aiohttp raises ContentTypeError when we ask for JSON.
            raise aiohttp.ClientError("rate limit")

        client.client.execute_async = fake_query  # type: ignore[assignment]
        with self.assertRaises(IndexerError) as ctx:
            _run(client.query("{x}", {}))
        self.assertIn("rate limit", str(ctx.exception))

    def test_query_does_not_swallow_programmer_errors(self):
        """Bugs in the caller (e.g. TypeError) must propagate, not become IndexerError."""
        client = IndexerClient("http://mock.invalid/graphql")

        async def fake_query(query, variables):
            raise TypeError("oops, unhashable variables")

        client.client.execute_async = fake_query  # type: ignore[assignment]
        with self.assertRaises(TypeError):
            _run(client.query("{x}", {}))

    def test_bearer_token_is_set(self):
        client = IndexerClient("http://mock.invalid/graphql", bearer_token="secret")
        self.assertEqual(client.client.headers.get("Authorization"), "Bearer secret")


class RestClientTests(unittest.TestCase):
    def test_account_404_raises_account_not_found(self):
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/resources"):
                return httpx.Response(404, text="missing")
            return httpx.Response(200, json={})

        client = _build_rest_client(handler)
        with self.assertRaises(AccountNotFound):
            _run(client.account_resources(AccountAddress.from_str_relaxed(SAMPLE_ADDR)))
        _run(client.close())

    def test_account_resource_404_raises_resource_not_found(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="missing")

        client = _build_rest_client(handler)
        with self.assertRaises(ResourceNotFound):
            _run(
                client.account_resource(
                    AccountAddress.from_str_relaxed(SAMPLE_ADDR), "0x1::coin::CoinStore"
                )
            )
        _run(client.close())

    def test_account_sequence_number_zero_on_404(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="missing")

        client = _build_rest_client(handler)
        seq = _run(client.account_sequence_number(AccountAddress.from_str_relaxed(SAMPLE_ADDR)))
        self.assertEqual(seq, 0)
        _run(client.close())

    def test_chain_id_caches(self):
        calls = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json={"chain_id": 233})

        client = _build_rest_client(handler)
        self.assertEqual(_run(client.chain_id()), 233)
        self.assertEqual(_run(client.chain_id()), 233)
        self.assertEqual(calls["n"], 1)
        _run(client.close())

    def test_api_key_sets_authorization_header(self):
        client = RestClient("http://mock.invalid", ClientConfig(api_key="abc", http2=False))
        self.assertEqual(client.client.headers.get("Authorization"), "Bearer abc")
        _run(client.close())

    def test_account_balance_decodes_view_response(self):
        def handler(req: httpx.Request) -> httpx.Response:
            assert req.url.path.endswith("/view")
            return httpx.Response(200, json=["12345"])

        client = _build_rest_client(handler)
        bal = _run(client.account_balance(AccountAddress.from_str_relaxed(SAMPLE_ADDR)))
        self.assertEqual(bal, 12345)
        _run(client.close())

    def test_view_returns_raw_bytes(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=["0x1"])

        client = _build_rest_client(handler)
        result = _run(client.view("0x1::coin::balance", [], [SAMPLE_ADDR]))
        self.assertIn(b"0x1", result)
        _run(client.close())

    def test_view_error_raises(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal")

        client = _build_rest_client(handler)
        with self.assertRaises(ApiError):
            _run(client.view("0x1::x::y", [], []))
        _run(client.close())

    def test_aggregator_value_traverses_resource(self):
        resource = {
            "data": {
                "supply": {
                    "vec": [
                        {
                            "aggregator": {
                                "vec": [{"handle": "0x1", "key": "0x2"}],
                            }
                        }
                    ]
                }
            }
        }

        def handler(req: httpx.Request) -> httpx.Response:
            if "/resource/" in req.url.path:
                return httpx.Response(200, json=resource)
            if "/tables/" in req.url.path:
                return httpx.Response(200, json="42")
            return httpx.Response(404)

        client = _build_rest_client(handler)
        v = _run(
            client.aggregator_value(
                AccountAddress.from_str_relaxed(SAMPLE_ADDR),
                "0x1::coin::CoinInfo",
                ["supply"],
            )
        )
        self.assertEqual(v, 42)
        _run(client.close())

    def test_aggregator_value_missing_path_raises(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"supply": {"vec": []}}})

        client = _build_rest_client(handler)
        with self.assertRaises(ApiError):
            _run(
                client.aggregator_value(
                    AccountAddress.from_str_relaxed(SAMPLE_ADDR),
                    "0x1::coin::CoinInfo",
                    ["supply"],
                )
            )
        _run(client.close())

    def test_wait_for_transaction_timeout(self):
        def handler(req: httpx.Request) -> httpx.Response:
            # Always pending → triggers timeout.
            return httpx.Response(200, json={"type": "pending_transaction"})

        client = _build_rest_client(handler)
        with self.assertRaises(TransactionTimeout):
            _run(client.wait_for_transaction("0xabc"))
        _run(client.close())

    def test_wait_for_transaction_failure(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"type": "user_transaction", "success": False})

        client = _build_rest_client(handler)
        with self.assertRaises(TransactionFailed):
            _run(client.wait_for_transaction("0xabc"))
        _run(client.close())

    def test_transaction_pending_404_returns_true(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="missing")

        client = _build_rest_client(handler)
        self.assertTrue(_run(client.transaction_pending("0xabc")))
        _run(client.close())

    def test_blocks_and_events_round_trip_errors(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="bad")

        client = _build_rest_client(handler)
        for coro in (
            client.blocks_by_height(0),
            client.blocks_by_version(0),
            client.event_by_creation_number(AccountAddress.from_str_relaxed(SAMPLE_ADDR), 0),
            client.events_by_event_handle(
                AccountAddress.from_str_relaxed(SAMPLE_ADDR), "0x1::x::Y", "f"
            ),
            client.transactions(),
            client.transactions_by_account(AccountAddress.from_str_relaxed(SAMPLE_ADDR)),
            client.transaction_by_hash("0x1"),
            client.transaction_by_version(0),
            client.account_module(AccountAddress.from_str_relaxed(SAMPLE_ADDR), "coin"),
        ):
            with self.assertRaises(ApiError):
                _run(coro)
        _run(client.close())


class FaucetClientTests(unittest.TestCase):
    def _client(self, handler):
        rest = _build_rest_client(handler, base_url="http://node.invalid/v1")
        return FaucetClient("http://faucet.invalid", rest, auth_token="tok")

    def test_fund_account_success(self):
        seen_paths = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen_paths.append(req.url.path)
            if req.url.path.endswith("/fund"):
                return httpx.Response(200, json={"txn_hashes": ["0xabc"]})
            # wait_for_transaction calls
            return httpx.Response(200, json={"type": "user_transaction", "success": True})

        c = self._client(handler)
        h = _run(c.fund_account(AccountAddress.from_str_relaxed(SAMPLE_ADDR), 100))
        self.assertEqual(h, "0xabc")
        self.assertTrue(any(p.endswith("/fund") for p in seen_paths))
        _run(c.close())

    def test_fund_account_failure_raises(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(429, text="rate limited")

        c = self._client(handler)
        with self.assertRaises(ApiError):
            _run(c.fund_account(AccountAddress.from_str_relaxed(SAMPLE_ADDR), 100))
        _run(c.close())

    def test_healthy_returns_false_on_error(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="bad")

        c = self._client(handler)
        self.assertFalse(_run(c.healthy()))
        _run(c.close())

    def test_healthy_returns_true_on_ok(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="tap:ok")

        c = self._client(handler)
        self.assertTrue(_run(c.healthy()))
        _run(c.close())


class PackagePublisherTests(unittest.TestCase):
    def test_create_chunks_splits_input(self):
        data = b"x" * (MAX_TRANSACTION_SIZE * 2 + 5)
        chunks = PackagePublisher.create_chunks(data)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(b"".join(chunks), data)
        self.assertEqual(len(chunks[0]), MAX_TRANSACTION_SIZE)

    def test_is_large_package(self):
        small = b"x" * 100
        self.assertFalse(PackagePublisher.is_large_package(small, [small]))
        big = b"x" * (MAX_TRANSACTION_SIZE + 1)
        self.assertTrue(PackagePublisher.is_large_package(big, []))

    def test_create_object_deployment_address_is_deterministic(self):
        addr = AccountAddress.from_str_relaxed("0x1")
        a = PackagePublisher.create_object_deployment_address(addr, 1)
        b = PackagePublisher.create_object_deployment_address(addr, 1)
        c = PackagePublisher.create_object_deployment_address(addr, 2)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_large_package_payload_is_an_entry_function(self):
        addr = AccountAddress.from_str_relaxed("0x1")
        payload = PackagePublisher.create_large_package_publishing_payload(
            addr, b"meta", [0, 1], [b"m0", b"m1"], True
        )
        self.assertIsInstance(payload, TransactionPayload)
        self.assertEqual(payload.variant, TransactionPayload.SCRIPT_FUNCTION)
        self.assertIsInstance(payload.value, EntryFunction)
        self.assertEqual(payload.value.function, "stage_code")

    def test_publish_mode_enum(self):
        self.assertEqual(PublishMode.ACCOUNT_DEPLOY.value, "ACCOUNT_DEPLOY")
        self.assertEqual(PublishMode.OBJECT_DEPLOY.value, "OBJECT_DEPLOY")
        self.assertEqual(PublishMode.OBJECT_UPGRADE.value, "OBJECT_UPGRADE")

    def test_publish_package_in_path_requires_code_object_for_upgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "build", "demo", "bytecode_modules"))
            with open(os.path.join(tmp, "Move.toml"), "wb") as f:
                f.write(b'[package]\nname = "demo"\n')
            with open(os.path.join(tmp, "build", "demo", "package-metadata.bcs"), "wb") as f:
                f.write(b"meta")
            with open(os.path.join(tmp, "build", "demo", "bytecode_modules", "m.mv"), "wb") as f:
                f.write(b"\xfe\xfe")

            client = mock.Mock(spec=RestClient)
            publisher = PackagePublisher(client)
            with self.assertRaises(ValueError):
                _run(
                    publisher.publish_package_in_path(
                        Account.generate(),
                        tmp,
                        publish_mode=PublishMode.OBJECT_UPGRADE,
                    )
                )

    def test_object_code_deployment_domain_separator_constant(self):
        # This must never change; on-chain object addresses are derived from it.
        self.assertEqual(
            OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR,
            b"aptos_framework::object_code_deployment",
        )


class CliTests(unittest.TestCase):
    def test_key_value_parses_pair(self):
        name, addr = key_value("foo=0x1")
        self.assertEqual(name, "foo")
        self.assertEqual(addr, AccountAddress.from_str("0x1"))

    def test_key_value_invalid_raises(self):
        with self.assertRaises(ValueError):
            key_value("no-equal-sign")


class AptosTokenClientPropertyTests(unittest.TestCase):
    def test_property_round_trip_all_types(self):
        addr = AccountAddress.from_str_relaxed("0x1")
        cases = [
            (Property.bool("a", True), Property.BOOL),
            (Property.u8("a", 1), Property.U8),
            (Property.u16("a", 1), Property.U16),
            (Property.u32("a", 1), Property.U32),
            (Property.u64("a", 1), Property.U64),
            (Property.u128("a", 1), Property.U128),
            (Property.u256("a", 1), Property.U256),
            (Property("a", "address", addr), Property.ADDRESS),
            (Property.string("a", "hello"), Property.STRING),
            (Property.bytes("a", b"\x01"), Property.BYTE_VECTOR),
        ]
        for prop, type_id in cases:
            data = prop.serialize_value()
            parsed = Property.parse(prop.name, type_id, data)
            self.assertEqual(parsed.value, prop.value)
            self.assertEqual(parsed.property_type, prop.property_type)
            args = prop.to_transaction_arguments()
            self.assertEqual(len(args), 3)
            for arg in args:
                self.assertIsInstance(arg, TransactionArgument)

    def test_property_invalid_type_raises(self):
        with self.assertRaises(InvalidPropertyType):
            Property("a", "weird", 1).serialize_value()
        with self.assertRaises(InvalidPropertyType):
            Property.parse("a", 99, b"")

    def test_property_map_to_tuple(self):
        pmap = PropertyMap([Property.u64("a", 1), Property.string("b", "x")])
        names, types, values = pmap.to_tuple()
        self.assertEqual(names, ["a", "b"])
        self.assertEqual(types, ["u64", "0x1::string::String"])
        self.assertEqual(len(values), 2)
        self.assertIn("Property", str(pmap))

    def test_property_map_parse(self):
        # Build the on-chain shape: each value has hex-encoded BCS bytes.
        prop_bytes = "0x" + Property.u64("x", 7).serialize_value().hex()
        resource = {
            "inner": {"data": [{"key": "x", "value": {"type": Property.U64, "value": prop_bytes}}]}
        }
        pm = PropertyMap.parse(resource)
        self.assertEqual(pm.properties[0].name, "x")
        self.assertEqual(pm.properties[0].value, 7)


class AptosTokenClientReadObjectTests(unittest.TestCase):
    def test_read_object_dispatches_resources(self):
        addr = AccountAddress.from_str_relaxed("0x1")
        resources = [
            {
                "type": Object.struct_tag,
                "data": {"allow_ungated_transfer": True, "owner": str(addr)},
            },
            {
                "type": Royalty.struct_tag,
                "data": {"numerator": "1", "denominator": "10", "payee_address": str(addr)},
            },
            {
                "type": Collection.struct_tag,
                "data": {
                    "creator": str(addr),
                    "description": "d",
                    "name": "n",
                    "uri": "u",
                },
            },
            {
                "type": Token.struct_tag,
                "data": {
                    "collection": {"inner": str(addr)},
                    "index": "5",
                    "description": "d",
                    "name": "n",
                    "uri": "u",
                },
            },
            {"type": "0x1::other::Thing", "data": {}},
        ]

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=resources)

        client = _build_rest_client(handler)
        token_client = AptosTokenClient(client)
        result = _run(token_client.read_object(addr))
        self.assertIsInstance(result, ReadObject)
        self.assertEqual(len(result.resources), 4)
        self.assertIn("ReadObject", str(result))
        # Each parsed type should expose its struct_tag.
        for cls in (Object, Royalty, Collection, Token):
            self.assertIn(cls, result.resources)
        _run(client.close())

    def test_collection_and_token_string(self):
        addr = AccountAddress.from_str_relaxed("0x1")
        c = Collection(addr, "d", "n", "u")
        self.assertIn("creator:", str(c))
        t = Token(addr, 1, "d", "n", "u")
        self.assertIn("collection:", str(t))
        o = Object(True, addr)
        self.assertIn("owner:", str(o))
        r = Royalty(1, 10, addr)
        self.assertIn("payee_address:", str(r))


class AptosTokenV1ClientTests(unittest.TestCase):
    def _make(self, handler):
        client = _build_rest_client(handler)
        return AptosTokenV1Client(client), client

    def test_get_token_balance_uses_table(self):
        def handler(req: httpx.Request) -> httpx.Response:
            if "/resource/" in req.url.path:
                return httpx.Response(200, json={"data": {"tokens": {"handle": "0xdead"}}})
            if "/tables/" in req.url.path:
                return httpx.Response(200, json={"amount": "9"})
            return httpx.Response(404)

        token_client, client = self._make(handler)
        addr = AccountAddress.from_str_relaxed(SAMPLE_ADDR)
        bal = _run(token_client.get_token_balance(addr, addr, "C", "T", "0"))
        self.assertEqual(bal, "9")
        _run(client.close())

    def test_get_collection_returns_data(self):
        payload = {"name": "C"}

        def handler(req: httpx.Request) -> httpx.Response:
            if "/resource/" in req.url.path:
                return httpx.Response(200, json={"data": {"collection_data": {"handle": "0xbeef"}}})
            if "/tables/" in req.url.path:
                return httpx.Response(200, json=payload)
            return httpx.Response(404)

        token_client, client = self._make(handler)
        addr = AccountAddress.from_str_relaxed(SAMPLE_ADDR)
        result = _run(token_client.get_collection(addr, "C"))
        self.assertEqual(result, payload)
        _run(client.close())


class SignedTransactionTests(unittest.TestCase):
    def test_str_includes_components(self):
        sk = ed25519.PrivateKey.random()
        sender = AccountAddress.from_key(sk.public_key())
        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::aptos_account",
                "transfer",
                [],
                [
                    TransactionArgument(sender, Serializer.struct),
                    TransactionArgument(1, Serializer.u64),
                ],
            )
        )
        raw = RawTransaction(sender, 0, payload, 1000, 1, 2_000_000_000, 4)
        auth = raw.sign(sk)
        signed = SignedTransaction(raw, auth)
        self.assertIn("Transaction", str(signed))
        self.assertEqual(signed, SignedTransaction(raw, auth))
        self.assertNotEqual(signed, "x")

    def test_simulated_signature_is_zero(self):
        sk = ed25519.PrivateKey.random()
        sender = AccountAddress.from_key(sk.public_key())
        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::aptos_account",
                "transfer",
                [],
                [
                    TransactionArgument(sender, Serializer.struct),
                    TransactionArgument(1, Serializer.u64),
                ],
            )
        )
        raw = RawTransaction(sender, 0, payload, 1000, 1, 2_000_000_000, 4)
        auth = raw.sign_simulated(sk.public_key())
        signed = SignedTransaction(raw, auth)
        # Simulated signature is all zeros; verify() must therefore fail.
        self.assertFalse(signed.verify())


class AccountAuthenticatorTests(unittest.TestCase):
    def test_authenticator_invalid_type_raises(self):
        with self.assertRaises(InvalidTypeError):
            Authenticator(object())

    def test_authenticator_round_trip(self):
        sk = ed25519.PrivateKey.random()
        ed_auth = Ed25519Authenticator(sk.public_key(), sk.sign(b"x"))
        outer = Authenticator(ed_auth)
        ser = Serializer()
        outer.serialize(ser)
        out = Authenticator.deserialize(Deserializer(ser.output()))
        self.assertEqual(outer, out)
        self.assertIn("PublicKey", str(outer))

    def test_invalid_authenticator_variant_in_stream(self):
        ser = Serializer()
        ser.uleb128(99)
        with self.assertRaises(InvalidTypeError):
            Authenticator.deserialize(Deserializer(ser.output()))

    def test_multi_agent_secondary_addresses(self):
        sk = ed25519.PrivateKey.random()
        addr = AccountAddress.from_key(sk.public_key())
        ed_auth = Ed25519Authenticator(sk.public_key(), sk.sign(b"x"))
        from .authenticator import AccountAuthenticator

        ma = MultiAgentAuthenticator(
            AccountAuthenticator(ed_auth),
            [(addr, AccountAuthenticator(ed_auth))],
        )
        self.assertEqual(ma.secondary_addresses(), [addr])


class AccountStoreLoadTests(unittest.TestCase):
    def test_account_store_then_load_round_trip(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            path = f.name
        try:
            a = Account.generate()
            a.store(path)
            with open(path) as fh:
                data = json.load(fh)
            self.assertIn("account_address", data)
            b = Account.load(path)
            self.assertEqual(a, b)
        finally:
            os.unlink(path)

    def test_account_eq_returns_not_implemented(self):
        a = Account.generate()
        self.assertNotEqual(a, "x")

    def test_secp256k1_account_address_derives(self):
        a = Account.generate_secp256k1_ecdsa()
        wrapped = asymmetric_crypto_wrapper.PublicKey(a.public_key())
        self.assertEqual(a.address(), AccountAddress.from_key(wrapped))


class RestClientTransactionHelpersTests(unittest.TestCase):
    """Exercise the transaction-submission helpers using a mocked transport."""

    def _client(self, handler):
        return _build_rest_client(handler)

    def test_submit_bcs_transaction_returns_hash(self):
        sk = ed25519.PrivateKey.random()
        sender = AccountAddress.from_key(sk.public_key())
        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::aptos_account",
                "transfer",
                [],
                [
                    TransactionArgument(sender, Serializer.struct),
                    TransactionArgument(1, Serializer.u64),
                ],
            )
        )
        raw = RawTransaction(sender, 0, payload, 1000, 1, 2_000_000_000, 4)
        signed = SignedTransaction(raw, raw.sign(sk))

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(202, json={"hash": "0xface"})

        client = self._client(handler)
        h = _run(client.submit_bcs_transaction(signed))
        self.assertEqual(h, "0xface")
        _run(client.close())

    def test_submit_bcs_transaction_error(self):
        sk = ed25519.PrivateKey.random()
        sender = AccountAddress.from_key(sk.public_key())
        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::aptos_account",
                "transfer",
                [],
                [
                    TransactionArgument(sender, Serializer.struct),
                    TransactionArgument(1, Serializer.u64),
                ],
            )
        )
        raw = RawTransaction(sender, 0, payload, 1000, 1, 2_000_000_000, 4)
        signed = SignedTransaction(raw, raw.sign(sk))

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="bad")

        client = self._client(handler)
        with self.assertRaises(ApiError):
            _run(client.submit_bcs_transaction(signed))
        _run(client.close())

    def test_simulate_bcs_transaction(self):
        sk = ed25519.PrivateKey.random()
        sender = AccountAddress.from_key(sk.public_key())
        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::aptos_account",
                "transfer",
                [],
                [
                    TransactionArgument(sender, Serializer.struct),
                    TransactionArgument(1, Serializer.u64),
                ],
            )
        )
        raw = RawTransaction(sender, 0, payload, 1000, 1, 2_000_000_000, 4)
        signed = SignedTransaction(raw, raw.sign(sk))

        params_seen: list[dict] = []

        def handler(req: httpx.Request) -> httpx.Response:
            params_seen.append(dict(req.url.params))
            return httpx.Response(200, json=[{"success": True}])

        client = self._client(handler)
        out = _run(client.simulate_bcs_transaction(signed, estimate_gas_usage=True))
        self.assertEqual(out, [{"success": True}])
        self.assertIn("estimate_gas_unit_price", params_seen[0])
        # Test simulate_transaction (uses sign_simulated)
        out2 = _run(client.simulate_transaction(raw, Account(sender, sk)))
        self.assertEqual(out2[0]["success"], True)
        _run(client.close())

    def test_create_bcs_signed_transaction_uses_address_only(self):
        seq_calls: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seq_calls.append(req.url.path)
            if "/accounts/" in req.url.path and req.url.path.endswith(SAMPLE_ADDR):
                return httpx.Response(200, json={"sequence_number": "5"})
            return httpx.Response(200, json={"chain_id": 4})

        client = self._client(handler)
        sk = ed25519.PrivateKey.random()
        sender = AccountAddress.from_str_relaxed(SAMPLE_ADDR)
        # Pre-cache chain id to avoid extra RPCs.
        client._chain_id = 4
        raw = _run(
            client.create_bcs_transaction(
                sender,
                TransactionPayload(
                    EntryFunction.natural(
                        "0x1::aptos_account",
                        "transfer",
                        [],
                        [
                            TransactionArgument(sender, Serializer.struct),
                            TransactionArgument(1, Serializer.u64),
                        ],
                    )
                ),
            )
        )
        self.assertEqual(raw.sequence_number, 5)
        self.assertEqual(raw.chain_id, 4)
        # Account-form sender path (covers `if isinstance(sender, Account)`).
        signed = _run(
            client.create_bcs_signed_transaction(
                Account(sender, sk),
                TransactionPayload(
                    EntryFunction.natural(
                        "0x1::aptos_account",
                        "transfer",
                        [],
                        [
                            TransactionArgument(sender, Serializer.struct),
                            TransactionArgument(2, Serializer.u64),
                        ],
                    )
                ),
                sequence_number=11,
            )
        )
        self.assertEqual(signed.transaction.sequence_number, 11)
        _run(client.close())

    def test_transfer_helpers_submit_signed_transaction(self):
        sk = ed25519.PrivateKey.random()
        sender = Account(AccountAddress.from_key(sk.public_key()), sk)

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/transactions") and req.method == "POST":
                return httpx.Response(202, json={"hash": "0x1234"})
            if "/accounts/" in req.url.path:
                return httpx.Response(200, json={"sequence_number": "0"})
            return httpx.Response(200, json={"chain_id": 4})

        client = self._client(handler)
        client._chain_id = 4
        recipient = AccountAddress.from_str_relaxed(SAMPLE_ADDR)
        h = _run(client.bcs_transfer(sender, recipient, 100))
        self.assertEqual(h, "0x1234")
        h2 = _run(client.transfer_coins(sender, recipient, "0x1::aptos_coin::AptosCoin", 100))
        self.assertEqual(h2, "0x1234")
        h3 = _run(client.transfer_object(sender, recipient, recipient))
        self.assertEqual(h3, "0x1234")
        _run(client.close())


class TokenV1ClientHelpersTests(unittest.TestCase):
    """Exercise AptosTokenV1Client helpers via a mocked REST client."""

    def setUp(self) -> None:
        self.sk = ed25519.PrivateKey.random()
        self.account = Account(AccountAddress.from_key(self.sk.public_key()), self.sk)
        self.recipient = AccountAddress.from_str_relaxed(SAMPLE_ADDR)

    def _client(self, handler):
        client = _build_rest_client(handler)
        client._chain_id = 4
        return AptosTokenV1Client(client), client

    def _post_returns_hash(self, req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path.endswith("/transactions"):
            return httpx.Response(202, json={"hash": "0xtoken"})
        if "/accounts/" in req.url.path:
            return httpx.Response(200, json={"sequence_number": "0"})
        return httpx.Response(200, json={"chain_id": 4})

    def test_create_collection(self):
        tc, c = self._client(self._post_returns_hash)
        h = _run(tc.create_collection(self.account, "n", "d", "u"))
        self.assertEqual(h, "0xtoken")
        _run(c.close())

    def test_create_token(self):
        tc, c = self._client(self._post_returns_hash)
        h = _run(tc.create_token(self.account, "C", "T", "d", 1, "u", 0))
        self.assertEqual(h, "0xtoken")
        _run(c.close())

    def test_offer_and_claim_token(self):
        tc, c = self._client(self._post_returns_hash)
        h = _run(tc.offer_token(self.account, self.recipient, self.recipient, "C", "T", 0, 1))
        self.assertEqual(h, "0xtoken")
        h2 = _run(tc.claim_token(self.account, self.recipient, self.recipient, "C", "T", 0))
        self.assertEqual(h2, "0xtoken")
        _run(c.close())

    def test_direct_transfer_token(self):
        receiver_sk = ed25519.PrivateKey.random()
        receiver = Account(AccountAddress.from_key(receiver_sk.public_key()), receiver_sk)
        tc, c = self._client(self._post_returns_hash)
        h = _run(tc.direct_transfer_token(self.account, receiver, self.recipient, "C", "T", 0, 1))
        self.assertEqual(h, "0xtoken")
        _run(c.close())

    def test_transfer_object(self):
        tc, c = self._client(self._post_returns_hash)
        h = _run(tc.transfer_object(self.account, self.recipient, self.recipient))
        self.assertEqual(h, "0xtoken")
        _run(c.close())

    def test_get_token_returns_zero_amount_on_404(self):
        def handler(req: httpx.Request) -> httpx.Response:
            if "/resource/" in req.url.path:
                return httpx.Response(200, json={"data": {"tokens": {"handle": "0xh"}}})
            return httpx.Response(404)

        tc, c = self._client(handler)
        info = _run(tc.get_token(self.recipient, self.recipient, "C", "T", 0))
        self.assertEqual(info["amount"], "0")
        _run(c.close())

    def test_get_token_data(self):
        def handler(req: httpx.Request) -> httpx.Response:
            if "/resource/" in req.url.path:
                return httpx.Response(200, json={"data": {"token_data": {"handle": "0xh"}}})
            return httpx.Response(200, json={"name": "T"})

        tc, c = self._client(handler)
        out = _run(tc.get_token_data(self.recipient, "C", "T", 0))
        self.assertEqual(out, {"name": "T"})
        _run(c.close())


class TokenClientPayloadTests(unittest.TestCase):
    """Exercise AptosTokenClient v2 payload constructors and submit helpers."""

    def setUp(self) -> None:
        self.sk = ed25519.PrivateKey.random()
        self.account = Account(AccountAddress.from_key(self.sk.public_key()), self.sk)
        self.addr = AccountAddress.from_str_relaxed(SAMPLE_ADDR)

    def _client(self):
        def handler(req: httpx.Request) -> httpx.Response:
            if req.method == "POST" and req.url.path.endswith("/transactions"):
                return httpx.Response(202, json={"hash": "0xtok2"})
            if "/accounts/" in req.url.path:
                return httpx.Response(200, json={"sequence_number": "0"})
            return httpx.Response(200, json={"chain_id": 4})

        rest = _build_rest_client(handler)
        rest._chain_id = 4
        return AptosTokenClient(rest), rest

    def test_create_collection_payload_round_trip(self):
        payload = AptosTokenClient.create_collection_payload(
            "desc", 100, "n", "u", *([True] * 9), 5, 100
        )
        self.assertIsInstance(payload, TransactionPayload)
        self.assertEqual(payload.value.function, "create_collection")

    def test_create_collection_submits(self):
        tc, c = self._client()
        h = _run(
            tc.create_collection(
                self.account,
                "desc",
                100,
                "n",
                "u",
                True,
                True,
                True,
                True,
                True,
                True,
                True,
                True,
                True,
                5,
                100,
            )
        )
        self.assertEqual(h, "0xtok2")
        _run(c.close())

    def test_mint_token(self):
        tc, c = self._client()
        h = _run(
            tc.mint_token(self.account, "C", "d", "T", "u", PropertyMap([Property.u64("a", 1)]))
        )
        self.assertEqual(h, "0xtok2")
        _run(c.close())

    def test_burn_token(self):
        tc, c = self._client()
        h = _run(tc.burn_token(self.account, self.addr))
        self.assertEqual(h, "0xtok2")
        _run(c.close())

    def test_freeze_unfreeze_transfer_token(self):
        tc, c = self._client()
        for fn in (
            tc.freeze_token,
            tc.unfreeze_token,
        ):
            h = _run(fn(self.account, self.addr))
            self.assertEqual(h, "0xtok2")
        h = _run(tc.transfer_token(self.account, self.addr, self.addr))
        self.assertEqual(h, "0xtok2")
        _run(c.close())

    def test_property_management(self):
        tc, c = self._client()
        prop = Property.u64("k", 5)
        for coro in (
            tc.add_token_property(self.account, self.addr, prop),
            tc.update_token_property(self.account, self.addr, prop),
            tc.remove_token_property(self.account, self.addr, "k"),
        ):
            self.assertEqual(_run(coro), "0xtok2")
        _run(c.close())


class PackagePublisherSubmitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sk = ed25519.PrivateKey.random()
        self.account = Account(AccountAddress.from_key(self.sk.public_key()), self.sk)

    def _client(self):
        def handler(req: httpx.Request) -> httpx.Response:
            if req.method == "POST" and req.url.path.endswith("/transactions"):
                return httpx.Response(202, json={"hash": "0xpub"})
            if "/accounts/" in req.url.path and req.url.path.endswith(
                "/transactions/by_hash/0xpub"
            ):
                return httpx.Response(200, json={"type": "user_transaction", "success": True})
            if "/transactions/by_hash/" in req.url.path:
                return httpx.Response(200, json={"type": "user_transaction", "success": True})
            if "/accounts/" in req.url.path:
                return httpx.Response(200, json={"sequence_number": "0"})
            return httpx.Response(200, json={"chain_id": 4})

        rest = _build_rest_client(handler)
        rest._chain_id = 4
        return PackagePublisher(rest), rest

    def test_publish_package_submits(self):
        pub, c = self._client()
        h = _run(pub.publish_package(self.account, b"meta", [b"m"]))
        self.assertEqual(h, "0xpub")
        _run(c.close())

    def test_publish_package_to_object(self):
        pub, c = self._client()
        h = _run(pub.publish_package_to_object(self.account, b"meta", [b"m"]))
        self.assertEqual(h, "0xpub")
        _run(c.close())

    def test_upgrade_package_object(self):
        pub, c = self._client()
        addr = AccountAddress.from_str_relaxed(SAMPLE_ADDR)
        h = _run(pub.upgrade_package_object(self.account, b"meta", [b"m"], addr))
        self.assertEqual(h, "0xpub")
        _run(c.close())

    def test_publish_package_in_path_account_deploy(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "build", "demo", "bytecode_modules"))
            with open(os.path.join(tmp, "Move.toml"), "wb") as f:
                f.write(b'[package]\nname = "demo"\n')
            with open(os.path.join(tmp, "build", "demo", "package-metadata.bcs"), "wb") as f:
                f.write(b"meta")
            with open(os.path.join(tmp, "build", "demo", "bytecode_modules", "m.mv"), "wb") as f:
                f.write(b"\xfe\xfe")
            pub, c = self._client()
            hashes = _run(pub.publish_package_in_path(self.account, tmp))
            self.assertEqual(hashes, ["0xpub"])
            _run(c.close())

    def test_chunked_package_publish(self):
        pub, c = self._client()
        big_meta = b"\x00" * (MAX_TRANSACTION_SIZE + 100)
        big_module = b"\xff" * (MAX_TRANSACTION_SIZE + 100)
        hashes = _run(pub.chunked_package_publish(self.account, big_meta, [big_module]))
        # Multiple stage_code transactions plus the final publish.
        self.assertGreaterEqual(len(hashes), 2)
        self.assertEqual(hashes[0], "0xpub")
        _run(c.close())


class CliWrapperTests(unittest.TestCase):
    def test_prepare_named_addresses(self):
        addr = AccountAddress.from_str("0x1")
        from .aptos_cli_wrapper import AptosCLIWrapper

        self.assertEqual(AptosCLIWrapper.prepare_named_addresses({}), [])
        out = AptosCLIWrapper.prepare_named_addresses({"a": addr, "b": addr})
        self.assertEqual(out[0], "--named-addresses")
        # The first pair gets a comma, the last does not.
        self.assertTrue(out[1].endswith(","))
        self.assertFalse(out[2].endswith(","))

    def test_does_cli_exist_returns_bool(self):
        from .aptos_cli_wrapper import AptosCLIWrapper

        self.assertIsInstance(AptosCLIWrapper.does_cli_exist(), bool)

    def test_assert_cli_exists_raises_when_absent(self):
        from .aptos_cli_wrapper import AptosCLIWrapper, MissingCLIError

        with mock.patch.object(AptosCLIWrapper, "does_cli_exist", return_value=False):
            with self.assertRaises(MissingCLIError):
                AptosCLIWrapper.assert_cli_exists()

    def test_compile_package_raises_on_failure(self):
        from .aptos_cli_wrapper import AptosCLIWrapper, CLIError

        with (
            mock.patch.object(AptosCLIWrapper, "assert_cli_exists"),
            mock.patch("aptos_sdk.aptos_cli_wrapper.subprocess.run") as run_mock,
        ):
            run_mock.return_value = mock.Mock(returncode=1, stdout=b"", stderr=b"oops")
            with self.assertRaises(CLIError):
                AptosCLIWrapper.compile_package("/nonexistent", {})

    def test_test_package_success(self):
        from .aptos_cli_wrapper import AptosCLIWrapper

        with (
            mock.patch.object(AptosCLIWrapper, "assert_cli_exists"),
            mock.patch("aptos_sdk.aptos_cli_wrapper.subprocess.run") as run_mock,
        ):
            run_mock.return_value = mock.Mock(returncode=0)
            AptosCLIWrapper.test_package("/x", {})
            run_mock.assert_called_once()


class CliMainTests(unittest.TestCase):
    """Cover the argparse main() entrypoint without invoking the actual CLI."""

    def test_main_publish_package_invokes_publisher(self):
        from . import cli as cli_mod

        with tempfile.NamedTemporaryFile("w", suffix=".key", delete=False) as f:
            sk = ed25519.PrivateKey.random()
            f.write(str(sk))
            key_path = f.name
        try:
            with (
                mock.patch.object(cli_mod.AptosCLIWrapper, "does_cli_exist", return_value=True),
                mock.patch.object(cli_mod.AptosCLIWrapper, "compile_package"),
                mock.patch.object(
                    cli_mod.PackagePublisher, "publish_package_in_path", new=mock.AsyncMock()
                ) as pub_mock,
            ):
                _run(
                    cli_mod.main(
                        [
                            "publish-package",
                            "--account",
                            "0x1",
                            "--package-dir",
                            "/tmp/x",
                            "--rest-api",
                            "http://node.invalid/v1",
                            "--private-key-path",
                            key_path,
                            "--named-address",
                            "foo=0x1",
                        ]
                    )
                )
                pub_mock.assert_awaited()
        finally:
            os.unlink(key_path)

    def test_main_errors_when_cli_missing(self):
        from . import cli as cli_mod

        with mock.patch.object(cli_mod.AptosCLIWrapper, "does_cli_exist", return_value=False):
            with self.assertRaises(SystemExit):
                _run(
                    cli_mod.main(
                        [
                            "publish-package",
                            "--account",
                            "0x1",
                            "--package-dir",
                            "/tmp/x",
                            "--rest-api",
                            "http://node.invalid/v1",
                        ]
                    )
                )

    def test_main_requires_package_dir(self):
        from . import cli as cli_mod

        with self.assertRaises(SystemExit):
            _run(cli_mod.main(["publish-package", "--account", "0x1"]))


class AsyncClientExtraEndpointsTests(unittest.TestCase):
    """Cover endpoints that weren't yet exercised: account_module, blocks, events, etc."""

    def test_account_module_success(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"abi": {"name": "coin"}})

        client = _build_rest_client(handler)
        out = _run(client.account_module(AccountAddress.from_str_relaxed(SAMPLE_ADDR), "coin"))
        self.assertEqual(out["abi"]["name"], "coin")
        _run(client.close())

    def test_account_modules_success(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"abi": {"name": "coin"}}])

        client = _build_rest_client(handler)
        out = _run(client.account_modules(AccountAddress.from_str_relaxed(SAMPLE_ADDR)))
        self.assertEqual(len(out), 1)
        _run(client.close())

    def test_blocks_and_events_success(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"x": 1})

        client = _build_rest_client(handler)
        self.assertEqual(_run(client.blocks_by_height(0)), {"x": 1})
        self.assertEqual(_run(client.blocks_by_version(0, with_transactions=True)), {"x": 1})
        _run(client.close())

    def test_get_table_item_success(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"v": "ok"})

        client = _build_rest_client(handler)
        out = _run(client.get_table_item("0xh", "address", "u128", "0x1"))
        self.assertEqual(out["v"], "ok")
        _run(client.close())

    def test_get_table_item_error(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="bad")

        client = _build_rest_client(handler)
        with self.assertRaises(ApiError):
            _run(client.get_table_item("0xh", "address", "u128", "0x1"))
        _run(client.close())

    def test_account_transaction_sequence_number_status(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"type": "user_transaction"}])

        client = _build_rest_client(handler)
        ok = _run(
            client.account_transaction_sequence_number_status(
                AccountAddress.from_str_relaxed(SAMPLE_ADDR), 0
            )
        )
        self.assertTrue(ok)
        _run(client.close())

    def test_current_timestamp(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ledger_timestamp": "1000000000"})

        client = _build_rest_client(handler)
        ts = _run(client.current_timestamp())
        self.assertAlmostEqual(ts, 1000.0, places=2)
        _run(client.close())

    def test_create_multi_agent_bcs_transaction(self):
        sk1 = ed25519.PrivateKey.random()
        sk2 = ed25519.PrivateKey.random()
        a1 = Account(AccountAddress.from_key(sk1.public_key()), sk1)
        a2 = Account(AccountAddress.from_key(sk2.public_key()), sk2)

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"sequence_number": "0"})

        client = _build_rest_client(handler)
        client._chain_id = 4
        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::aptos_account",
                "transfer",
                [],
                [
                    TransactionArgument(a2.address(), Serializer.struct),
                    TransactionArgument(1, Serializer.u64),
                ],
            )
        )
        signed = _run(client.create_multi_agent_bcs_transaction(a1, [a2], payload))
        self.assertIsInstance(signed, SignedTransaction)
        self.assertTrue(signed.verify())
        _run(client.close())

    def test_submit_and_wait_for_bcs_transaction(self):
        sk = ed25519.PrivateKey.random()
        sender = AccountAddress.from_key(sk.public_key())
        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::aptos_account",
                "transfer",
                [],
                [
                    TransactionArgument(sender, Serializer.struct),
                    TransactionArgument(1, Serializer.u64),
                ],
            )
        )
        raw = RawTransaction(sender, 0, payload, 1000, 1, 2_000_000_000, 4)
        signed = SignedTransaction(raw, raw.sign(sk))

        def handler(req: httpx.Request) -> httpx.Response:
            if req.method == "POST" and req.url.path.endswith("/transactions"):
                return httpx.Response(202, json={"hash": "0xab"})
            return httpx.Response(200, json={"type": "user_transaction", "success": True})

        client = _build_rest_client(handler)
        out = _run(client.submit_and_wait_for_bcs_transaction(signed))
        self.assertTrue(out["success"])
        _run(client.close())


class FeePayerAuthenticatorTests(unittest.TestCase):
    def test_fee_payer_authenticator_round_trip(self):
        sk = ed25519.PrivateKey.random()
        addr = AccountAddress.from_key(sk.public_key())
        sig = sk.sign(b"x")
        from .authenticator import (
            AccountAuthenticator,
            Ed25519Authenticator,
        )

        ed = Ed25519Authenticator(sk.public_key(), sig)
        sender = AccountAuthenticator(ed)
        fp = FeePayerAuthenticator(sender, [(addr, sender)], (addr, sender))
        # fee_payer_address & secondary_addresses
        self.assertEqual(fp.fee_payer_address(), addr)
        self.assertEqual(fp.secondary_addresses(), [addr])

        ser = Serializer()
        fp.serialize(ser)
        out = FeePayerAuthenticator.deserialize(Deserializer(ser.output()))
        self.assertEqual(fp, out)
        self.assertNotEqual(fp, "x")
        # MultiAgent verify path
        ma = MultiAgentAuthenticator(sender, [(addr, sender)])
        ser = Serializer()
        ma.serialize(ser)
        out_ma = MultiAgentAuthenticator.deserialize(Deserializer(ser.output()))
        self.assertEqual(ma.secondary_addresses(), out_ma.secondary_addresses())

    def test_single_sender_authenticator_round_trip(self):
        sk = ed25519.PrivateKey.random()
        from .authenticator import AccountAuthenticator, Ed25519Authenticator

        ed = Ed25519Authenticator(sk.public_key(), sk.sign(b"x"))
        ss = SingleSenderAuthenticator(AccountAuthenticator(ed))
        ser = Serializer()
        ss.serialize(ser)
        out = SingleSenderAuthenticator.deserialize(Deserializer(ser.output()))
        self.assertEqual(ss, out)


class MetadataAndErrorsTests(unittest.TestCase):
    def test_metadata_header_value(self):
        from .metadata import Metadata

        v = Metadata.get_aptos_header_val()
        self.assertIn("python", v.lower())

    def test_api_error_attributes(self):
        e = ApiError("nope", 503)
        self.assertEqual(e.status_code, 503)
        self.assertIn("nope", str(e))


if __name__ == "__main__":
    unittest.main()
