# Aptos Python SDK Changelog

All notable changes to the Aptos Python SDK will be captured in this file. This changelog is written by hand for now.

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

