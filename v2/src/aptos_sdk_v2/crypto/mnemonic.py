"""BIP-39 mnemonic phrase support with BIP-44 key derivation."""

from __future__ import annotations

from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39WordsNum,
    Bip44,
    Bip44Changes,
    Bip44Coins,
)

from ..errors import InvalidMnemonicError
from .ed25519 import Ed25519PrivateKey
from .secp256k1 import Secp256k1PrivateKey

# Aptos BIP-44 path: m/44'/637'/0'/0'/0'
DEFAULT_DERIVATION_PATH = "m/44'/637'/0'/0'/0'"


def generate_mnemonic(word_count: int = 12) -> str:
    """Generate a new BIP-39 mnemonic phrase."""
    match word_count:
        case 12:
            words_num = Bip39WordsNum.WORDS_NUM_12
        case 24:
            words_num = Bip39WordsNum.WORDS_NUM_24
        case _:
            raise ValueError("Word count must be 12 or 24")
    return str(Bip39MnemonicGenerator().FromWordsNumber(words_num))


def validate_mnemonic(phrase: str) -> bool:
    """Check if a mnemonic phrase is valid."""
    return Bip39MnemonicValidator().IsValid(phrase)


def derive_ed25519_private_key(
    phrase: str,
    path: str = DEFAULT_DERIVATION_PATH,
) -> Ed25519PrivateKey:
    """Derive an Ed25519 private key from a mnemonic phrase using SLIP-0010 (BIP-44)."""
    if not validate_mnemonic(phrase):
        raise InvalidMnemonicError("Invalid mnemonic phrase")

    seed = Bip39SeedGenerator(phrase).Generate()

    # Parse the BIP-44 derivation path: m/purpose'/coin'/account'/change'/address'
    parts = path.replace("'", "").split("/")
    if len(parts) < 6 or parts[0] != "m":
        raise InvalidMnemonicError(
            f"Invalid derivation path: {path}. "
            "Expected BIP-44 format: m/44'/637'/account'/change'/address'"
        )

    account_idx = int(parts[3])
    address_idx = int(parts[5])

    bip44_ctx = (
        Bip44.FromSeed(seed, Bip44Coins.APTOS)
        .Purpose()
        .Coin()
        .Account(account_idx)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(address_idx)
    )

    raw_key = bip44_ctx.PrivateKey().Raw().ToBytes()
    return Ed25519PrivateKey.from_hex(raw_key)


def derive_secp256k1_private_key(
    phrase: str,
    path: str = DEFAULT_DERIVATION_PATH,
) -> Secp256k1PrivateKey:
    """Derive a Secp256k1 private key from a mnemonic phrase using BIP-32/BIP-44."""
    if not validate_mnemonic(phrase):
        raise InvalidMnemonicError("Invalid mnemonic phrase")

    seed = Bip39SeedGenerator(phrase).Generate()

    # Parse the BIP-44 derivation path: m/purpose'/coin'/account'/change'/address'
    parts = path.replace("'", "").split("/")
    if len(parts) < 6 or parts[0] != "m":
        raise InvalidMnemonicError(
            f"Invalid derivation path: {path}. "
            "Expected BIP-44 format: m/44'/637'/account'/change'/address'"
        )

    account_idx = int(parts[3])
    address_idx = int(parts[5])

    bip44_ctx = (
        Bip44.FromSeed(seed, Bip44Coins.APTOS)
        .Purpose()
        .Coin()
        .Account(account_idx)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(address_idx)
    )

    raw_key = bip44_ctx.PrivateKey().Raw().ToBytes()
    return Secp256k1PrivateKey.from_hex(raw_key)
