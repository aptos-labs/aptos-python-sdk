"""
Authentication Key Rotation Example for Aptos Python SDK.

This example demonstrates how to perform authentication key rotation on the Aptos
blockchain, showcasing both single-key and multi-key rotation scenarios. Authentication
key rotation allows changing the private key that controls an account while keeping
the same account address, providing crucial security and recovery capabilities.

Key rotation is essential for:
    - **Key Compromise Recovery**: When a private key is suspected to be compromised
    - **Proactive Security**: Periodic key rotation as a security best practice
    - **Key Management**: Transitioning from single keys to multi-signature setups
    - **Access Transfer**: Transferring account control to different parties
    - **Emergency Recovery**: Recovering access using backup keys

Features Demonstrated:
    - Single Ed25519 key rotation from one private key to another
    - Multi-signature key rotation from single key to multi-key setup
    - Rotation proof challenge generation and signing
    - Authentication key validation after rotation
    - Account reconstruction with new private keys
    - On-chain verification of rotation completion

Key Concepts:
    - **Authentication Key**: The key that proves ownership of an account
    - **Account Address**: Remains constant even after key rotation
    - **Rotation Proof**: Cryptographic proof that the current key holder
      authorizes the key change
    - **Dual Signatures**: Both current and new keys must sign the rotation proof
    - **Multi-Key Migration**: Transitioning from single to multi-signature control

Security Model:
    The rotation process requires signatures from both:
    1. **Current Key**: Proves current control of the account
    2. **New Key**: Proves possession of the new private key

    This dual-signature requirement prevents unauthorized key rotations even
    if an attacker knows the new private key but not the current one.

Workflow Overview:
    1. **Setup Phase**:
       - Generate accounts (Alice as primary, Bob's key as rotation target)
       - Fund Alice's account for transaction fees
       - Display initial account states

    2. **Single Key Rotation**:
       - Create rotation proof challenge with sequence number and addresses
       - Sign the challenge with both current (Alice) and new (Bob) keys
       - Submit rotation transaction to the blockchain
       - Verify authentication key change on-chain
       - Reconstruct Alice's account object with new private key

    3. **Multi-Key Migration**:
       - Create multi-key setup combining multiple Ed25519 keys
       - Generate rotation proof for single-to-multi transition
       - Submit multi-key rotation transaction
       - Validate the new multi-signature authentication key

Rotation Proof Challenge Components:
    - **Sequence Number**: Current account sequence to prevent replay attacks
    - **Originator**: The account address being rotated
    - **Current Auth Key**: The authentication key being replaced
    - **New Public Key**: The public key portion of the replacement key

Transaction Structure:
    The rotation transaction calls `0x1::account::rotate_authentication_key` with:
    - Authentication schemes for both keys (current and new)
    - Public keys for both current and new authentication
    - Signatures from both keys proving authorization

Security Considerations:
    - **Private Key Protection**: Store rotation keys securely
    - **Replay Protection**: Each rotation uses current sequence number
    - **Atomic Operations**: Rotation either succeeds completely or fails
    - **Verification**: Always verify rotation completion on-chain
    - **Key Material**: Securely dispose of old private keys after rotation

Common Use Cases:
    - **Suspected Compromise**: Immediate rotation to new secure keys
    - **Operational Security**: Periodic key rotation policies
    - **Multi-Sig Migration**: Moving high-value accounts to multi-signature
    - **Recovery Operations**: Using backup keys to regain account access
    - **Organizational Changes**: Transferring control between team members

Error Scenarios:
    - Invalid signatures in rotation proof
    - Insufficient account balance for transaction fees
    - Network connectivity issues during submission
    - Sequence number mismatches (replay protection)
    - Malformed rotation proof challenges

Prerequisites:
    - Active Aptos network connection (devnet/testnet)
    - Faucet access for funding transaction fees
    - Understanding of Ed25519 cryptographic signatures
    - Knowledge of account authentication mechanisms

Usage:
    Run this script to see authentication key rotation in action:
        python3 examples/rotate_key.py

Expected Output:
    - Formatted display of account information before rotation
    - Progress indicators during rotation operations
    - Updated account information after each rotation
    - Verification of successful authentication key changes
    - Final multi-signature authentication key confirmation

Learning Objectives:
    - Master authentication key rotation mechanics
    - Understand dual-signature security requirements
    - Practice single-to-multi-key migrations
    - Learn rotation proof challenge construction
    - Gain experience with advanced account security patterns

Related Examples:
    - multikey.py: Multi-signature account creation and usage
    - hello_blockchain.py: Basic account and transaction patterns
    - authenticate.py: Authentication and signature verification
    - multisig.py: Legacy multi-signature account patterns
"""

import asyncio
from typing import List, cast

import aptos_sdk.asymmetric_crypto as asymmetric_crypto
import aptos_sdk.ed25519 as ed25519
from aptos_sdk.account import Account, RotationProofChallenge
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import FaucetClient, RestClient
from aptos_sdk.authenticator import Authenticator
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)

from .common import FAUCET_AUTH_TOKEN, FAUCET_URL, NODE_URL

WIDTH = 19


def truncate(address: str) -> str:
    """
    Truncate a long address string for display purposes.

    Takes a long address string and returns a shortened version showing
    only the first 6 and last 6 characters, with "..." in between.
    This is useful for displaying addresses in formatted tables.

    Args:
        address: The full address string to truncate.

    Returns:
        A shortened string in the format "123abc...def456".

    Example:
        >>> truncate("***23456789abcdef")
        "***23...def"
    """
    return address[0:6] + "..." + address[-6:]


def format_account_info(account: Account) -> str:
    """
    Format account information for tabular display.

    Extracts key information from an Account object and formats it
    into a fixed-width string suitable for table display. Each field
    is truncated and left-justified to maintain consistent formatting.

    Args:
        account: The Account object to format.

    Returns:
        A formatted string containing truncated account information
        with consistent spacing for table display.

    The formatted string contains:
        - Account address (truncated)
        - Authentication key (truncated)
        - Private key hex representation (truncated)
        - Public key string representation (truncated)

    Example Output:
        "***bcd...456    ***def...789    abc123...xyz    ed25519..."
    """
    vals = [
        str(account.address()),
        account.auth_key(),
        account.private_key.hex(),
        str(account.public_key()),
    ]
    return "".join([truncate(v).ljust(WIDTH, " ") for v in vals])


async def rotate_auth_key_ed_25519_payload(
    rest_client: RestClient, from_account: Account, private_key: ed25519.PrivateKey
) -> TransactionPayload:
    to_account = Account.load_key(private_key.hex())
    rotation_proof_challenge = RotationProofChallenge(
        sequence_number=await rest_client.account_sequence_number(
            from_account.address()
        ),
        originator=from_account.address(),
        current_auth_key=AccountAddress.from_str_relaxed(from_account.auth_key()),
        new_public_key=to_account.public_key(),
    )

    serializer = Serializer()
    rotation_proof_challenge.serialize(serializer)
    rotation_proof_challenge_bcs = serializer.output()

    from_signature = from_account.sign(rotation_proof_challenge_bcs)
    to_signature = to_account.sign(rotation_proof_challenge_bcs)

    return rotation_payload(
        from_account.public_key(), to_account.public_key(), from_signature, to_signature
    )


async def rotate_auth_key_multi_ed_25519_payload(
    rest_client: RestClient,
    from_account: Account,
    private_keys: List[ed25519.PrivateKey],
) -> TransactionPayload:
    to_accounts = list(
        map(lambda private_key: Account.load_key(private_key.hex()), private_keys)
    )
    public_keys = list(map(lambda account: account.public_key(), to_accounts))
    public_key = ed25519.MultiPublicKey(cast(List[ed25519.PublicKey], public_keys), 1)

    rotation_proof_challenge = RotationProofChallenge(
        sequence_number=await rest_client.account_sequence_number(
            from_account.address()
        ),
        originator=from_account.address(),
        current_auth_key=AccountAddress.from_str(from_account.auth_key()),
        new_public_key=public_key,
    )

    serializer = Serializer()
    rotation_proof_challenge.serialize(serializer)
    rotation_proof_challenge_bcs = serializer.output()

    from_signature = from_account.sign(rotation_proof_challenge_bcs)
    to_signature = cast(
        ed25519.Signature, to_accounts[0].sign(rotation_proof_challenge_bcs)
    )
    multi_to_signature = ed25519.MultiSignature.from_key_map(
        public_key,
        [(cast(ed25519.PublicKey, to_accounts[0].public_key()), to_signature)],
    )

    return rotation_payload(
        from_account.public_key(), public_key, from_signature, multi_to_signature
    )


def rotation_payload(
    from_key: asymmetric_crypto.PublicKey,
    to_key: asymmetric_crypto.PublicKey,
    from_signature: asymmetric_crypto.Signature,
    to_signature: asymmetric_crypto.Signature,
) -> TransactionPayload:
    from_scheme = Authenticator.from_key(from_key)
    to_scheme = Authenticator.from_key(to_key)

    entry_function = EntryFunction.natural(
        module="0x1::account",
        function="rotate_authentication_key",
        ty_args=[],
        args=[
            TransactionArgument(from_scheme, Serializer.u8),
            TransactionArgument(from_key, Serializer.struct),
            TransactionArgument(to_scheme, Serializer.u8),
            TransactionArgument(to_key, Serializer.struct),
            TransactionArgument(from_signature, Serializer.struct),
            TransactionArgument(to_signature, Serializer.struct),
        ],
    )

    return TransactionPayload(entry_function)


async def main():
    # Initialize the clients used to interact with the blockchain
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN)

    # Generate random accounts Alice and Bob
    alice = Account.generate()
    bob = Account.generate()

    # Fund Alice's account, since we don't use Bob's
    await faucet_client.fund_account(alice.address(), 100_000_000)

    # Display formatted account info
    print(
        "\n"
        + "Account".ljust(WIDTH, " ")
        + "Address".ljust(WIDTH, " ")
        + "Auth Key".ljust(WIDTH, " ")
        + "Private Key".ljust(WIDTH, " ")
        + "Public Key".ljust(WIDTH, " ")
    )
    print(
        "-------------------------------------------------------------------------------------------"
    )
    print("Alice".ljust(WIDTH, " ") + format_account_info(alice))
    print("Bob".ljust(WIDTH, " ") + format_account_info(bob))

    print("\n...rotating...\n")

    # :!:>rotate_key
    # Create the payload for rotating Alice's private key to Bob's private key
    payload = await rotate_auth_key_ed_25519_payload(
        rest_client, alice, bob.private_key
    )
    # Have Alice sign the transaction with the payload
    signed_transaction = await rest_client.create_bcs_signed_transaction(alice, payload)
    # Submit the transaction and wait for confirmation
    tx_hash = await rest_client.submit_bcs_transaction(signed_transaction)
    await rest_client.wait_for_transaction(tx_hash)  # <:!:rotate_key

    # Check the authentication key for Alice's address on-chain
    alice_new_account_info = await rest_client.account(alice.address())
    # Ensure that Alice's authentication key matches bob's
    assert (
        alice_new_account_info["authentication_key"] == bob.auth_key()
    ), "Authentication key doesn't match Bob's"

    # Construct a new Account object that reflects alice's original address with the new private key
    original_alice_key = alice.private_key
    alice = Account(alice.address(), bob.private_key)

    # Display formatted account info
    print("Alice".ljust(WIDTH, " ") + format_account_info(alice))
    print("Bob".ljust(WIDTH, " ") + format_account_info(bob))
    print()

    print("\n...rotating...\n")
    payload = await rotate_auth_key_multi_ed_25519_payload(
        rest_client, alice, [bob.private_key, original_alice_key]
    )
    signed_transaction = await rest_client.create_bcs_signed_transaction(alice, payload)
    tx_hash = await rest_client.submit_bcs_transaction(signed_transaction)
    await rest_client.wait_for_transaction(tx_hash)

    alice_new_account_info = await rest_client.account(alice.address())
    auth_key = alice_new_account_info["authentication_key"]
    print(f"Rotation to MultiPublicKey complete, new authkey: {auth_key}")

    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
