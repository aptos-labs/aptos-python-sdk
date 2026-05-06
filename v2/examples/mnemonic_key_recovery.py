"""Example: BIP-39 mnemonic key generation, validation, and recovery.

Demonstrates the full mnemonic wallet workflow:
- Generate a 12-word mnemonic phrase
- Validate a mnemonic phrase
- Derive the default account
- Prove determinism: re-derive the same address from the same phrase
- Multi-account derivation by varying the BIP-44 path index
- Secp256k1 mnemonic derivation
- Full round-trip: generate wallet → fund → restore from phrase → transact
"""

import asyncio

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network
from aptos_sdk_v2.crypto.mnemonic import (
    DEFAULT_DERIVATION_PATH,
    generate_mnemonic,
    validate_mnemonic,
)


async def main():
    # ── Generate and validate a mnemonic ────────────────────────────────
    phrase = generate_mnemonic()  # 12 words by default
    print(f"Generated mnemonic: {phrase}")
    print(f"Word count: {len(phrase.split())}")
    print(f"Valid: {validate_mnemonic(phrase)}")
    print(f"Default derivation path: {DEFAULT_DERIVATION_PATH}")

    # You can also generate a 24-word mnemonic for extra entropy:
    # phrase_24 = generate_mnemonic(word_count=24)

    # Validate an invalid phrase (returns False, does not raise)
    print(f"\nInvalid phrase check: {validate_mnemonic('not a valid mnemonic')}")

    # ── Derive the default account ──────────────────────────────────────
    account = Account.from_mnemonic(phrase)
    print(f"\nDefault account (Ed25519):")
    print(f"  Address: {account.address}")
    print(f"  Public key type: {type(account.public_key).__name__}")

    # ── Prove determinism ───────────────────────────────────────────────
    # The same mnemonic + path always produces the same account
    account_again = Account.from_mnemonic(phrase)
    assert account.address == account_again.address, "Addresses should match!"
    print(f"\nDeterministic re-derivation: {account_again.address} (matches: True)")

    # ── Multi-account derivation ────────────────────────────────────────
    # Vary the account index in the BIP-44 path: m/44'/637'/{i}'/0'/0'
    # This is how wallets derive multiple accounts from a single seed phrase
    print("\nMulti-account derivation:")
    for i in range(3):
        path = f"m/44'/637'/{i}'/0'/0'"
        acct = Account.from_mnemonic(phrase, path=path)
        print(f"  [{i}] {path} → {acct.address}")

    # ── Secp256k1 mnemonic derivation ───────────────────────────────────
    # Pass secp256k1=True to derive a Secp256k1 key instead of Ed25519
    secp_account = Account.from_mnemonic(phrase, secp256k1=True)
    print(f"\nSecp256k1 account from same mnemonic:")
    print(f"  Address: {secp_account.address}")
    print(f"  Public key type: {type(secp_account.public_key).__name__}")
    # Note: different key type = different address, even from the same phrase

    # ── Full round-trip: generate → fund → restore → transact ──────────
    print("\n── Full round-trip test ──")
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        # Step 1: Generate a new wallet from mnemonic
        wallet_phrase = generate_mnemonic()
        original = Account.from_mnemonic(wallet_phrase)
        recipient = Account.generate()
        print(f"Original wallet: {original.address}")
        print(f"Recipient:       {recipient.address}")

        # Step 2: Fund the wallet
        print("\nFunding wallet...")
        await aptos.faucet.fund_account(original.address, 100_000_000)
        await aptos.faucet.fund_account(recipient.address, 10_000_000)

        balance = await aptos.coin.balance(original.address)
        print(f"Wallet balance: {balance}")

        # Step 3: "Lose" the wallet and restore from phrase
        restored = Account.from_mnemonic(wallet_phrase)
        assert restored.address == original.address
        print(f"\nRestored wallet: {restored.address} (matches original: True)")

        # Step 4: Transact from the restored wallet
        print("Transferring 5000 octas from restored wallet...")
        txn_hash = await aptos.coin.transfer(restored, recipient.address, 5_000)
        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"Transaction: {txn_hash}")
        print(f"Success: {result['success']}")

        # Verify final balances
        wallet_balance = await aptos.coin.balance(restored.address)
        recipient_balance = await aptos.coin.balance(recipient.address)
        print(f"\nWallet balance:    {wallet_balance}")
        print(f"Recipient balance: {recipient_balance}")


if __name__ == "__main__":
    asyncio.run(main())
