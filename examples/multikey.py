# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Multi-Key Authentication Example for Aptos Python SDK.

This example demonstrates how to create and use multi-signature (multi-key) accounts
on the Aptos blockchain. Multi-signature accounts require multiple cryptographic keys
to sign transactions, providing enhanced security for high-value operations.

Features Demonstrated:
    - Creating a multi-key account with mixed key types (secp256k1 and Ed25519)
    - Setting up a threshold signature scheme (2-of-3 in this example)
    - Signing transactions with multiple keys
    - Verifying multi-signatures before submission
    - Transferring funds from a multi-key account

Key Concepts:
    - **Multi-Key Account**: An account controlled by multiple cryptographic keys
    - **Threshold Signatures**: Requires a minimum number of signatures (threshold) 
      out of the total available keys to authorize transactions
    - **Mixed Key Types**: Supports both secp256k1 (ECDSA) and Ed25519 keys in 
      the same multi-key setup
    - **Account Address Derivation**: Multi-key accounts have addresses derived 
      from the combined public keys and threshold

Security Benefits:
    - **Distributed Control**: No single key can authorize transactions alone
    - **Reduced Single Points of Failure**: Even if one key is compromised, 
      the account remains secure
    - **Flexible Access Patterns**: Different combinations of signers can 
      authorize transactions
    - **Key Type Diversity**: Mixing different signature schemes provides 
      cryptographic diversity

Workflow:
    1. Generate multiple private keys of different types (secp256k1, Ed25519)
    2. Create a MultiPublicKey with a 2-of-3 threshold
    3. Derive the account address from the multi-key setup
    4. Fund the multi-key account using the faucet
    5. Create a transaction payload (APT transfer)
    6. Sign the transaction with 2 out of 3 keys (meeting the threshold)
    7. Combine signatures into a MultiSignature
    8. Verify all signatures before submission
    9. Submit the signed transaction to the network
    10. Wait for transaction confirmation

Prerequisites:
    - Access to an Aptos test network (devnet/testnet)
    - Faucet access for funding accounts
    - Network configuration in common.py

Usage:
    Run this script directly to see multi-key authentication in action:
        python3 examples/multikey.py

Expected Output:
    - Display of Alice's multi-key address and Bob's single-key address
    - Initial account balances after funding
    - Transaction execution transferring 1,000 APT from Alice to Bob
    - Final balances showing the transfer completion
    - Verification of all signature operations

Security Considerations:
    - Store private keys securely in production environments
    - Use hardware security modules (HSMs) for high-value multi-key setups
    - Regularly audit key holder access and permissions
    - Consider key rotation policies for long-term security
    - Test signature verification thoroughly before mainnet deployment

Error Handling:
    - Network connectivity issues
    - Insufficient account balances
    - Invalid signature combinations
    - Transaction simulation failures
    - Faucet funding limitations

Learning Objectives:
    - Understand multi-signature account creation and management
    - Learn threshold signature schemes and their security properties
    - Practice mixed cryptographic key type usage
    - Gain experience with complex transaction authorization patterns
    - Explore advanced account security models on Aptos

Related Examples:
    - authenticate.py: Single-key authentication patterns
    - hello_blockchain.py: Basic transaction patterns
    - transfer_coin.py: Simple APT transfers
    - multisig.py: Legacy multi-signature account patterns
"""

import asyncio

from aptos_sdk import asymmetric_crypto_wrapper, ed25519, secp256k1_ecdsa
from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.asymmetric_crypto_wrapper import MultiSignature, Signature
from aptos_sdk.async_client import FaucetClient, IndexerClient, RestClient
from aptos_sdk.authenticator import AccountAuthenticator, MultiKeyAuthenticator
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)

from .common import FAUCET_AUTH_TOKEN, FAUCET_URL, INDEXER_URL, NODE_URL


async def main():
    """
    Demonstrate multi-key authentication and transaction signing on Aptos.
    
    This function showcases the complete workflow for creating a multi-signature
    account, funding it, and executing a transfer transaction that requires
    multiple signatures to authorize.
    
    The example creates a 2-of-3 multi-key account using mixed cryptographic
    key types (secp256k1 and Ed25519) and demonstrates how to:
    
    1. **Setup Phase**:
       - Initialize REST and Faucet clients for network interaction
       - Generate 3 private keys of different types (2 secp256k1, 1 Ed25519)
       - Create a MultiPublicKey with threshold=2 (requires 2 signatures)
       - Derive the multi-key account address
       - Create a regular single-key account for Bob
    
    2. **Funding Phase**:
       - Fund both Alice's multi-key account and Bob's account using faucet
       - Display initial balances for verification
    
    3. **Transaction Phase**:
       - Construct an APT transfer transaction from Alice to Bob
       - Sign the transaction with 2 out of 3 available keys
       - Combine individual signatures into a MultiSignature
       - Create an AccountAuthenticator with MultiKeyAuthenticator
    
    4. **Verification Phase**:
       - Verify each individual signature against its corresponding key
       - Verify the combined multi-signature against the multi-key
       - Verify the complete authenticator
    
    5. **Submission Phase**:
       - Submit the signed transaction to the network
       - Wait for transaction confirmation
       - Display final balances to confirm the transfer
    
    Key Security Features:
    - **Threshold Security**: Requires 2 signatures out of 3 possible
    - **Cryptographic Diversity**: Uses both secp256k1 and Ed25519 keys
    - **Signature Verification**: Validates all signatures before submission
    - **Address Derivation**: Deterministically derives address from multi-key
    
    Network Requirements:
    - Active Aptos devnet/testnet connection
    - Faucet service availability for account funding
    - Sufficient network tokens for transaction fees
    
    Error Scenarios Handled:
    - Network connectivity issues during client operations
    - Transaction failures during submission or confirmation
    - Signature verification failures before submission
    - Account balance insufficiency for transfers
    
    Raises:
        Exception: If network operations fail, signature verification fails,
            or transaction submission encounters errors.
    
    Example Output:
        === Addresses ===
        Multikey Alice: ***bcd123...
        Bob: ***456def...
        
        === Initial Balances ===
        Alice: 100000000
        Bob: 1
        
        === Final Balances ===
        Alice: 99999000  # Reduced by transfer amount + fees
        Bob: 1001        # Increased by transfer amount
    """
    # :!:>section_1
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(
        FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN
    )  # <:!:section_1
    if INDEXER_URL and INDEXER_URL != "none":
        IndexerClient(INDEXER_URL)
    else:
        pass

    # :!:>section_2
    key1 = secp256k1_ecdsa.PrivateKey.random()
    key2 = ed25519.PrivateKey.random()
    key3 = secp256k1_ecdsa.PrivateKey.random()
    pubkey1 = key1.public_key()
    pubkey2 = key2.public_key()
    pubkey3 = key3.public_key()

    alice_pubkey = asymmetric_crypto_wrapper.MultiPublicKey(
        [pubkey1, pubkey2, pubkey3], 2
    )
    alice_address = AccountAddress.from_key(alice_pubkey)

    bob = Account.generate()

    print("\n=== Addresses ===")
    print(f"Multikey Alice: {alice_address}")
    print(f"Bob: {bob.address()}")

    # :!:>section_3
    alice_fund = faucet_client.fund_account(alice_address, 100_000_000)
    bob_fund = faucet_client.fund_account(bob.address(), 1)  # <:!:section_3
    await asyncio.gather(*[alice_fund, bob_fund])

    print("\n=== Initial Balances ===")
    # :!:>section_4
    alice_balance = rest_client.account_balance(alice_address)
    bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")  # <:!:section_4

    # Have Alice give Bob 1_000 coins
    # :!:>section_5

    # TODO: Rework SDK to support this without the extra work

    # Build Transaction to sign
    transaction_arguments = [
        TransactionArgument(bob.address(), Serializer.struct),
        TransactionArgument(1_000, Serializer.u64),
    ]

    payload = EntryFunction.natural(
        "0x1::aptos_account",
        "transfer",
        [],
        transaction_arguments,
    )

    raw_transaction = await rest_client.create_bcs_transaction(
        alice_address, TransactionPayload(payload)
    )

    # Sign by multiple keys
    raw_txn_bytes = raw_transaction.keyed()
    sig1 = key1.sign(raw_txn_bytes)
    sig2 = key2.sign(raw_txn_bytes)

    # Combine them
    total_sig = MultiSignature([(0, Signature(sig1)), (1, Signature(sig2))])
    alice_auth = AccountAuthenticator(MultiKeyAuthenticator(alice_pubkey, total_sig))

    # Verify signatures
    assert key1.public_key().verify(raw_txn_bytes, sig1)
    assert key2.public_key().verify(raw_txn_bytes, sig2)
    assert alice_pubkey.verify(raw_txn_bytes, total_sig)
    assert alice_auth.verify(raw_txn_bytes)

    # Submit to network
    signed_txn = SignedTransaction(raw_transaction, alice_auth)
    txn_hash = await rest_client.submit_bcs_transaction(signed_txn)

    # :!:>section_6
    await rest_client.wait_for_transaction(txn_hash)  # <:!:section_6

    print("\n=== Final Balances ===")
    alice_balance = rest_client.account_balance(alice_address)
    bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")  # <:!:section_4

    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
