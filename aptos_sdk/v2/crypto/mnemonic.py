"""BIP-39 mnemonic phrase support with BIP-44 key derivation.

Implemented with the standard library only (``hashlib``/``hmac``/``secrets``)
so the SDK no longer depends on ``bip-utils``. That dependency transitively
pulled in ``ecdsa`` 0.19.2, which is subject to CVE-2024-23342 /
GHSA-wj6h-64fc-37mp (PYSEC-2026-1325, Minerva timing attack on P-256) with
no patched release -- upstream considers side-channel attacks out of scope.
It also pulled in ``coincurve`` and other packages that are no longer in
the install surface.

Derivation is byte-for-byte compatible with the previous ``bip-utils``
behaviour for Aptos (coin type 637): BIP-39 seed via PBKDF2-HMAC-SHA512,
then SLIP-0010 hardened derivation at every level of
``m/44'/637'/account'/0'/address'`` for both Ed25519 and Secp256k1 keys.
Compatibility is pinned by fixed test vectors in ``tests/unit/test_mnemonic.py``
that were generated with ``bip-utils``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import unicodedata

from ..errors import InvalidMnemonicError
from .bip39_wordlist import WORD_INDEX, WORDLIST
from .ed25519 import Ed25519PrivateKey
from .secp256k1 import Secp256k1PrivateKey

# Aptos BIP-44 path: m/44'/637'/0'/0'/0'
DEFAULT_DERIVATION_PATH = "m/44'/637'/0'/0'/0'"

_HARDENED_OFFSET = 0x80000000
_VALID_WORD_COUNTS = (12, 15, 18, 21, 24)


def generate_mnemonic(word_count: int = 12) -> str:
    """Generate a new BIP-39 mnemonic phrase."""
    match word_count:
        case 12:
            entropy_bits = 128
        case 24:
            entropy_bits = 256
        case _:
            raise ValueError("Word count must be 12 or 24")
    entropy = secrets.token_bytes(entropy_bits // 8)
    checksum_bits = entropy_bits // 32
    digest = hashlib.sha256(entropy).digest()
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(entropy_bits)
    bits += bin(digest[0])[2:].zfill(8)[:checksum_bits]
    words = [WORDLIST[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11)]
    return " ".join(words)


def validate_mnemonic(phrase: str) -> bool:
    """Check if a mnemonic phrase is valid."""
    words = phrase.split()
    if len(words) not in _VALID_WORD_COUNTS:
        return False
    try:
        indices = [WORD_INDEX[word] for word in words]
    except KeyError:
        return False
    bits = "".join(bin(index)[2:].zfill(11) for index in indices)
    checksum_bits = len(bits) // 33
    entropy_bits = len(bits) - checksum_bits
    entropy = int(bits[:entropy_bits], 2).to_bytes(entropy_bits // 8, "big")
    digest = hashlib.sha256(entropy).digest()
    expected = bin(digest[0])[2:].zfill(8)[:checksum_bits]
    return bits[entropy_bits:] == expected


def _seed_from_phrase(phrase: str) -> bytes:
    normalized = unicodedata.normalize("NFKD", phrase)
    return hashlib.pbkdf2_hmac("sha512", normalized.encode("utf-8"), b"mnemonic", 2048, dklen=64)


def _derive_slip10(seed: bytes, indices: list[int]) -> bytes:
    """SLIP-0010 hardened derivation (Ed25519 curve seed key)."""
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain_code = digest[:32], digest[32:]
    for index in indices:
        data = b"\x00" + key + (index + _HARDENED_OFFSET).to_bytes(4, "big")
        digest = hmac.new(chain_code, data, hashlib.sha512).digest()
        key, chain_code = digest[:32], digest[32:]
    return key


def _parse_path(path: str) -> tuple[int, int, int]:
    # Parse the BIP-44 derivation path: m/44'/637'/account'/change'/address'
    parts = path.replace("'", "").split("/")
    if len(parts) != 6 or parts[0] != "m" or parts[1] != "44" or parts[2] != "637":
        raise InvalidMnemonicError(
            f"Invalid derivation path: {path}. "
            "Expected BIP-44 format: m/44'/637'/account'/change'/address'"
        )
    try:
        account_idx = int(parts[3])
        change_idx = int(parts[4])
        address_idx = int(parts[5])
    except ValueError as exc:
        raise InvalidMnemonicError(
            f"Invalid derivation path: {path}. Non-numeric segment: {exc}"
        ) from exc
    if change_idx != 0:
        raise InvalidMnemonicError(
            f"Invalid derivation path: {path}. Aptos uses change index 0 (external chain) only."
        )
    if not (0 <= account_idx < _HARDENED_OFFSET and 0 <= address_idx < _HARDENED_OFFSET):
        raise InvalidMnemonicError(
            f"Invalid derivation path: {path}. Account and address indices must be in [0, 2^31)."
        )
    return account_idx, change_idx, address_idx


def _derive_raw_key(phrase: str, path: str) -> bytes:
    if not validate_mnemonic(phrase):
        raise InvalidMnemonicError("Invalid mnemonic phrase")
    account_idx, _change_idx, address_idx = _parse_path(path)
    seed = _seed_from_phrase(phrase)
    return _derive_slip10(seed, [44, 637, account_idx, 0, address_idx])


def derive_ed25519_private_key(
    phrase: str,
    path: str = DEFAULT_DERIVATION_PATH,
) -> Ed25519PrivateKey:
    """Derive an Ed25519 private key from a mnemonic phrase using SLIP-0010 (BIP-44)."""
    raw_key = _derive_raw_key(phrase, path)
    return Ed25519PrivateKey.from_hex(raw_key)


def derive_secp256k1_private_key(
    phrase: str,
    path: str = DEFAULT_DERIVATION_PATH,
) -> Secp256k1PrivateKey:
    """Derive a Secp256k1 private key from a mnemonic phrase using BIP-44.

    Uses the same SLIP-0010 derivation as Ed25519 (matching the previous
    ``bip-utils`` Aptos behaviour); the derived bytes are interpreted as a
    Secp256k1 private key.
    """
    raw_key = _derive_raw_key(phrase, path)
    return Secp256k1PrivateKey.from_hex(raw_key)
