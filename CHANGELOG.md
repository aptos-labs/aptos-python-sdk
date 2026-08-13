# Aptos Python SDK Changelog

All notable changes to the Aptos Python SDK will be captured in this file. This changelog is written by hand for now.

## Unreleased

- Make e2e / localnet examples more reliable: `aggregator_value` reads both OptionalAggregator variants (aggregator table and integer, as used on localnet), REST and faucet calls retry transient 429/5xx and faucet sequence-number races, and the integration harness waits for the node and reloads network env vars after starting a localnet.

## 0.12.0 (2026-07-02)

### Breaking changes

- **[Breaking Change]**: Minimum supported Python is now **3.12** (was 3.10+).
- **[Breaking Change]**: Replace `python-ecdsa` (CVE-2024-23342, pure-Python) with `cryptography` (OpenSSL-backed) for secp256k1 ECDSA operations. The public API is unchanged. Note: signing now uses OpenSSL's randomized nonce instead of RFC 6979 deterministic nonce — identical (key, message) pairs will produce different valid signatures on each call. `verify()` now rejects high-S signatures to match Aptos on-chain behaviour.
- **[Breaking Change — v2 only, key derivation]**: `aptos_sdk.v2.crypto.mnemonic.derive_ed25519_private_key` and `derive_secp256k1_private_key` now require the full BIP-44 path `m/purpose'/coin'/account'/change'/address'` and read the address index from segment 5 (`parts[5]`). The previous implementation read the *change* segment (`parts[4]`) as the address index and never called `.AddressIndex(...)`, so any non-zero address index was silently ignored and **every** mnemonic-derived account collapsed onto the index-0 key. After this fix, paths with a non-zero address index will derive a different private key (and therefore a different account address) than the old, broken code did. Users with on-chain state derived from a non-zero address index under the old code must migrate; users on the canonical `m/44'/637'/0'/0'/0'` path are unaffected.

### Added

- Add **`aptos_sdk.v2`** — an async-first v2 SDK subpackage with a modern API surface (`Aptos`, `AptosConfig`, `Network`, typed APIs for accounts, coins, fungible assets, transactions, and BCS). See [`MIGRATION.md`](MIGRATION.md) for a v1→v2 guide.
- Add `SignedTransaction.hash()` to v1 and v2 — compute the committed transaction hash locally without submitting to the network.
- Add `aptos_sdk.v2.types.TypeTag.from_str` parser supporting primitives (`bool`, `u8`–`u256`, `address`, `signer`), `vector<T>`, and structs. `GeneralApi.view_bcs` now uses it, so view functions with non-struct generics (e.g. `0x1::coin::balance<u64>`) work correctly.
- Add devnet E2E smoke example (`make smoke`) covering node, faucet, transaction submission, simulation, balance reads, and indexer.
- Add automated PyPI publishing on GitHub Release via OIDC trusted publishing (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

### Changed

- Increase default `max_gas_amount` from 100,000 to 1,000,000.
- Stricter `aptos_sdk.v2.transactions.payload.ModuleId.from_str` — rejects malformed inputs (wrong number of `::` separators, empty address, or empty module name) at parse time instead of failing later during BCS serialization.
- Stricter `aptos_sdk.async_client.IndexerClient.query` exception scope — only wraps known transport / decoding errors (`aiohttp.ClientError`, `asyncio.TimeoutError`, `json.JSONDecodeError`, `UnicodeDecodeError`) into `IndexerError`. Caller bugs (`TypeError`, `AttributeError`, etc.) propagate unchanged.
- `aptos_sdk.v2` balance queries use the REST API to support both legacy coins and fungible assets.
- BCS serialization, transaction signing, and type-tag parsing performance optimizations.
- Migrate build tooling from Poetry to **uv** + **hatchling**; lint/format with **ruff** and **mypy**.
- Apply ruff formatting across `aptos_sdk`, `examples`, and `features` stubs (enforced by CI `make fmt` gate).
- Update dependencies for vulnerability fixes (`aiohttp`, `urllib3`, `PyNaCl`, `cryptography`, `requests`).
- Adopt the Innovation-Enabling Source Code License from aptos-core.
- CI: test against Python 3.12 and 3.13; pin GitHub Actions; add Codecov v1/v2 coverage flags and v2-mirror sync enforcement; replace devnet examples CI with comprehensive localnet testing.

## 0.11.0

- **[Breaking Change]**: `ed25519` and `secp256k1` private key's `__str__` will now return the AIP-80 compliant string
- `PrivateKey.format_private_key` can now format a AIP-80 compliant private key
- Removed strictness warnnings for `PrivateKey.parse_hex_input`
- Make HTTP2 default
- Update all dependencies
- Add ability for `account_balance` with other coins
- Upgrade to Poetry 2.1.3

## 0.10.0

- Added support for deserialize RawTransactionWithData
- Added support for AIP-80 compliance for Ed25519 and Secp256k1 private keys.
- Added helper functions for AIP-80 including `PrivateKey.format_private_key` and `PrivateKey.parse_hex_input`

## 0.9.2
- Fix MultiKeyAuthenicator serialization and deserialization with tests

## 0.9.1
- For `account_sequence_number`, return 0 if account has yet to be created to better support sponsored transactions create account if not exists
- For `account_balance`, Use `0x1::coin::balance` instead of reading the resource

## 0.9.0
- Add Multikey support for Python, with an example
- Deprecate and remove non-BCS transaction submission
- Set max Uleb128 to MAX_U32
- Add Behave behavioral specifications for BCS and AccountAddress

## 0.8.6
- add client for graphql indexer service with light demo in coin transfer
- add mypy to ignore missing types for graphql and ecdsa
- remove `<4.0` requirement for python as this invariant blocks updates unnecessarily, for example, httpx was several versions behind
- remove h2 as it doesn't seem to be directly used
- add py.typed so that projects can add type checking when using the sdk
- fix tables api -- there was an extra `base_url`
- ClientConfig updates for bearer token
- Identified a TypeTag parsing issue where nested types weren't wrapped with TypeTag

## 0.8.1
- Improve TypeTag parsing for nested types
- Add BCS and String-based (JSON) view functions
- Added thorough documentation

## 0.8.0
- Add support for SingleKeyAuthenicatoin component of AIP-55
- Add support for Secp256k1 Ecdsa of AIP-49
- Add support for Sponsored transactions of AIP-39 and AIP-53
- Improved support for MultiEd25519

## 0.7.0
- **[Breaking Change]**: The `from_str` function on `AccountAddress` has been updated to conform to the strict parsing described by [AIP-40](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md). For the relaxed parsing behavior of this function prior to this change, use `AccountAddress.from_str_relaxed`.
- **[Breaking Change]**: Rewrote the large package publisher to support large modules too
- **[Breaking Change]**: Delete sync client
- **[Breaking Change]**: Removed the `hex` function from `AccountAddress`. Instead of `addr.hex()` use `str(addr)`.
- **[Breaking Change]**: The string representation of `AccountAddress` now conforms to [AIP-40](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md).
- **[Breaking Change]**: `AccountAddress.from_hex` and `PrivateKey.from_hex` have been renamed to `from_str`.
- Port remaining sync examples to async (hello-blockchain, multisig, your-coin)
- Updated token client to use events to acquire minted tokens
- Update many dependencies and set Python 3.8.1 as the minimum requirement
- Add support for an experimental chunked uploader
- Add experimental support for the Aptos CLI enabling local end-to-end testing, package building, and package integration tests

## 0.6.4
- Change sync client library from httpX to requests due to latency concerns.

## 0.6.2
- Added custom header "x-aptos-client" to both sync/async RestClient

## 0.6.1
- Updated package manifest.

## 0.6.0
- Add token client.
- Add support for generating account addresses.
- Add support for http2
- Add async client
