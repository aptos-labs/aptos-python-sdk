# Aptos Python SDK — Security Review

Date: 2026-05-15
Scope: `aptos_sdk/` (legacy v1 package), `v2/src/aptos_sdk_v2/` (standalone
v2 package), `examples/`, CI workflows, and packaging metadata.
Methodology: manual code review of every module, dependency surface analysis,
diff between the two v2 trees, runtime testing against devnet.

This document is informational and supersedes nothing in `SECURITY.md`. Report
true vulnerabilities through the channel defined there, not via PR.

---

## 1. Threat model

The SDK runs in a **trusted client process**: the user controls the host, the
private keys, and the network destination. Adversaries we care about are:

| # | Adversary | Plausible attack |
|---|-----------|------------------|
| A1 | Compromised dependency | Steal private keys at signing time, inject malicious BCS |
| A2 | Hostile RPC node | Return crafted JSON / BCS that crashes the client or causes incorrect signatures |
| A3 | Hostile faucet | Replay / mint to attacker addresses (out of scope for the SDK; the faucet is the trust root for funding on devnet/testnet) |
| A4 | MITM on HTTPS | TLS downgrade, cert tampering — relies on `httpx` defaults |
| A5 | Local file disclosure | Private-key JSON files left world-readable (`Account.store`) |
| A6 | Re-entrancy / reuse | Replay of a signed transaction |

The SDK does **not** defend against a compromised host or against an attacker
who already has the user's private key. Out of scope.

---

## 2. Findings

### 2.1 Resolved by this PR

| ID | Severity | Module | Issue | Fix |
|----|----------|--------|-------|-----|
| F-01 | **High** (correctness) | `aptos_sdk/transactions.py` | `ScriptArgument.__init__` rejected variants 6 (U16), 7 (U32), 8 (U256) even though `serialize`/`deserialize` supported them. Any caller passing a U16/U32/U256 script argument got `InvalidTypeError` at construction time, while bytes deserialized from chain crashed only on a later round-trip. | Widen variant range to `[0, 8]` and improve the error message. |
| F-02 | Medium | `aptos_sdk/asymmetric_crypto_wrapper.py` | `PublicKey.deserialize` checked `Signature.SECP256K1_ECDSA` rather than `PublicKey.SECP256K1_ECDSA`. Worked by accident (both equal `1`), but a future renumbering would silently accept invalid bytes. | Use the correct constant. |
| F-03 | Medium | `aptos_sdk/async_client.py` | `IndexerClient.query` propagated raw `aiohttp.ContentTypeError` when the indexer returned an HTML rate-limit page. Clients had no way to catch this generically. | Wrap in a new `IndexerError`; also raise `IndexerError` when the GraphQL response has a top-level `errors` array. |
| F-04 | Low | `aptos_sdk/async_client.py` | `FaucetClient.healthy` returned truthy for any 5xx response with body containing `tap:ok` (and crashed on transport errors). | Require `status_code == 200` and swallow `httpx.HTTPError` to return `False`. |
| F-05 | Low | `aptos_sdk/v2` mirror divergence | `aptos_sdk/v2/` had safety improvements (BIP-44 path validation, secp256k1 wrapping in `AuthenticationKey.from_public_key`, `ModuleId.from_str` validation) that were missing from `v2/src/aptos_sdk_v2/`. End users importing from the standalone package received the unsafe versions. | Port the fixes back to `v2/src/aptos_sdk_v2/`; add `.github/scripts/check_v2_sync.sh` and CI step to enforce mirror parity. |
| F-06 | Low | `examples/transaction_batching.py` | `Accounts.generate("nodes", ...)` crashed with `FileNotFoundError` because the `nodes/` directory was never created. Affects any user copy-pasting the example. | `os.makedirs(path, exist_ok=True)`. |
| F-07 | Informational | `examples/fee_payer_transfer_coin.py` | Comment said "Have Alice give Bob 1_000 coins" but the entry function actually called is `0x1::aptos_account::create_account` — no coins are transferred. | Comment corrected. |

### 2.2 Pre-existing risks worth noting

| ID | Severity | Module | Issue | Recommendation |
|----|----------|--------|-------|----------------|
| O-01 | Medium | `aptos_sdk/account.py` | `Account.store` writes the private key as plaintext JSON with default permissions (typically 0644 on Linux). Any user on the box can read it. | Document the risk; consider `os.chmod(path, 0o600)` and a warning log line. |
| O-02 | Medium | `aptos_sdk/asymmetric_crypto_wrapper.MultiPublicKey` | The `MultiPublicKey.verify` path does **not** ensure the same signer index isn't counted twice — a forged `MultiSignature` containing the same valid `(idx, sig)` twice would pass. | Add `seen = set()` deduplication; reject `idx >= len(keys)` (already done) and require unique indices. |
| O-03 | Medium | `aptos_sdk/async_client.RestClient` | All HTTP/2 connections share a single `httpx.AsyncClient` with no per-call API key rotation. `Authorization` is set once at client-construction time. If a long-lived process needs to rotate keys it has to construct a new client. | Document; consider exposing `set_api_key()`. |
| O-04 | Low | `aptos_sdk/async_client.RestClient.transaction_pending` | Treats HTTP 404 as "still pending" so `wait_for_transaction` will silently spin on a typo'd hash until it times out. | Bound the 404 grace window (e.g. accept 404 only for the first N polls, then escalate). |
| O-05 | Low | `aptos_sdk/async_client.RestClient` | No per-call timeout. Pool timeout is `None` ("wait forever for a slot"). A single hung request will block all subsequent ones. | Add a per-request timeout argument or align pool timeout with `transaction_wait_in_seconds`. |
| O-06 | Low | `aptos_sdk/aptos_cli_wrapper.py` | `CLIError.__init__` joins the entire `args` list (including potentially sensitive values like `--private-key-path`) into the exception message. | Redact `--private-key*` flags before logging. |
| O-07 | Low | `aptos_sdk/cli.py` | Reads private key from a path supplied via `--private-key-path` but doesn't check file permissions before opening. | Optional: warn if file is world-readable. |
| O-08 | Low | `aptos_sdk/transactions.py` | `RawTransaction` accepts arbitrary integer values for `chain_id` (u8 only). On a typo (e.g. `chain_id=1024`) BCS serialization will silently truncate or raise far from the source of the bug. | Validate `0 <= chain_id < 256` in `__init__`. |
| O-09 | Informational | `aptos_sdk/async_client.IndexerClient` | Bearer tokens are passed via the constructor and stored on the underlying GraphQL client headers. No secret-scrubbing on `__repr__`. | Override `__repr__` to redact. |

### 2.3 Dependency surface

`pyproject.toml` already pins minimum-secure floors for indirect dependencies
(`h11>=0.16.0`, `urllib3>=2.6.3`, `requests>=2.32.5`, `aiohttp>=3.13.3`).
That's good practice; keep these floors moving forward.

`bip-utils` (used by v2 mnemonic derivation) transitively pulls in
`coincurve`, which is a `setup.py`-style C-extension package. The v2 README
already flags `bip-utils` as the next dep to evict; coincurve in particular
has had a history of releasing wheels late on each Python minor bump and is
a useful target for supply-chain attackers because it's tiny and unaudited.
We replaced direct secp256k1 with `cryptography` in v2 — finishing the
`bip-utils` removal would close that surface entirely.

`python-graphql-client` (used by `IndexerClient`) is a thin wrapper over
`aiohttp` that hasn't seen a release in a long time. Consider replacing with
direct `httpx.AsyncClient.post`.

### 2.4 Cryptographic notes

* **Ed25519** — backed by PyNaCl (libsodium). No issues found.
* **Secp256k1** — backed by `cryptography` (OpenSSL via `hazmat`). Signing
  uses deterministic ECDSA per RFC 6979 (default in `cryptography`).
  ✅ Good.
* **Authentication-key derivation** — uses SHA3-256 with the documented
  scheme bytes (Ed25519=0x00, MultiEd25519=0x01, SingleKey=0x02,
  MultiKey=0x03). Matches the on-chain definition in `aptos-core`.
* **Domain separators** — `APTOS::RawTransaction` (single-signer) and
  `APTOS::RawTransactionWithData` (multi-agent / fee-payer) match
  `aptos-core`. Verified by the corpus tests in `aptos_sdk/transactions.py`.
* **Simulated-transaction signatures** are 64 zero bytes. The SDK correctly
  rejects them on `SignedTransaction.verify` so users cannot accidentally
  ship an unsigned transaction. ✅ Tested.

### 2.5 Network & TLS

* Default `httpx.AsyncClient` config trusts the system CA bundle and uses
  TLS 1.2+. Acceptable for the Aptos public endpoints which are HTTPS.
* HTTP/2 is enabled by default (`ClientConfig.http2 = True`). HTTP/2
  upgrade is opportunistic; downgrade attacks aren't trivially exploitable.
* The faucet and node URLs are taken from environment variables in
  `examples/common.py`. Users running examples in a CI environment should
  not export these to untrusted hosts.

### 2.6 What this SDK explicitly does **not** do

* It does not store, encrypt, or rotate private keys. `Account.store` writes
  cleartext JSON for convenience — production users should integrate with
  their own secrets manager (AWS Secrets Manager, GCP Secret Manager, HSM).
* It does not enforce any kind of replay protection beyond what the on-chain
  sequence number / orderless nonce provides.
* It does not validate that the configured RPC endpoint is on the chain the
  user expects beyond exposing `chain_id()`. Callers should pin a chain ID
  for production deployments.

---

## 3. Recommended follow-ups

The fixes in §2.1 land with this PR. The items in §2.2 are tracked here for a
follow-up PR / issue. In rough priority order:

1. **O-02** (MultiPublicKey replay): real signature-bypass vector if anyone
   wires the v1 SDK into a multi-sig server. High priority.
2. **O-04 / O-05**: hardening of the wait/timeout machinery so long-lived
   services don't deadlock on bad inputs.
3. **O-01 / O-07**: file-permission hygiene around `Account.store` and
   `--private-key-path`.
4. **O-08**: range checks on `RawTransaction` integer fields so user
   typos surface at the source.
5. Replace `python-graphql-client` and finish removing `bip-utils` from the
   v2 install surface (already flagged in `pyproject.toml`).
6. Reproducible build / wheel signing — currently `hatchling` builds wheels
   but they are not signed (Sigstore / `attestations`). Worth adding to
   `.github/workflows/publish.yaml` once a maintainer sets up a Sigstore
   identity.
