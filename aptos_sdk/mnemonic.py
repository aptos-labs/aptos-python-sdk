# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
BIP-39 mnemonic generation and SLIP-0010 key derivation for the Aptos Python SDK.

This module is a **P1 feature** that enables wallet-style HD key derivation
from a mnemonic seed phrase.

Public API
----------
generate_mnemonic(word_count)
    Generate a BIP-39 mnemonic phrase with the given word count.

validate_mnemonic(mnemonic)
    Return ``True`` if *mnemonic* is a valid BIP-39 phrase.

mnemonic_to_seed(mnemonic, passphrase)
    Derive a 64-byte BIP-39 seed from *mnemonic* using PBKDF2-HMAC-SHA512.

derive_key(seed, path)
    Derive a 32-byte Ed25519 private key from *seed* using SLIP-0010 and
    a BIP-44 derivation path.

SLIP-0010 Notes
---------------
Ed25519 keys only support **hardened** child-key derivation; non-hardened
paths are not permitted on this curve.  All path segments must be hardened
(i.e., end with ``"'"``).

The default Aptos derivation path is::

    m/44'/637'/0'/0'/0'

References
----------
- BIP-39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP-44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
- SLIP-0010: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
"""

import hashlib
import hmac

from .errors import InvalidInputError

# ---------------------------------------------------------------------------
# Default derivation path (Aptos coin type 637 per SLIP-0044)
# ---------------------------------------------------------------------------

DEFAULT_PATH: str = "m/44'/637'/0'/0'/0'"

# ---------------------------------------------------------------------------
# BIP-39 helpers
# ---------------------------------------------------------------------------


def generate_mnemonic(word_count: int = 12) -> str:
    """
    Generate a BIP-39 mnemonic phrase.

    Uses the ``mnemonic`` package for word-list management and entropy
    generation.

    Parameters
    ----------
    word_count:
        Number of words to generate.  Must be one of ``{12, 15, 18, 21, 24}``.
        Defaults to ``12``.

    Returns
    -------
    str
        A space-separated BIP-39 mnemonic phrase.

    Raises
    ------
    ImportError
        If the ``mnemonic`` package is not installed.  Install it with
        ``pip install mnemonic`` (or add it to your project dependencies).
    InvalidInputError
        If *word_count* is not one of the supported values.
    """
    valid_counts = {12, 15, 18, 21, 24}
    if word_count not in valid_counts:
        raise InvalidInputError(
            f"word_count must be one of {sorted(valid_counts)}, got {word_count}."
        )

    try:
        from mnemonic import Mnemonic  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "The 'mnemonic' package is required for mnemonic generation. "
            "Install it with: pip install mnemonic"
        ) from exc

    # BIP-39 strength is the entropy in bits.
    # word_count=12 → 128 bits, word_count=24 → 256 bits.
    # Formula: strength = word_count * 11 * 32 // 33
    strength = word_count * 11 * 32 // 33
    m = Mnemonic("english")
    return m.generate(strength)


def validate_mnemonic(mnemonic: str) -> bool:
    """
    Validate a BIP-39 mnemonic phrase.

    Parameters
    ----------
    mnemonic:
        A space-separated BIP-39 mnemonic string.

    Returns
    -------
    bool
        ``True`` if *mnemonic* is a valid BIP-39 phrase; ``False`` otherwise.

    Raises
    ------
    ImportError
        If the ``mnemonic`` package is not installed.
    """
    try:
        from mnemonic import Mnemonic  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "The 'mnemonic' package is required for mnemonic validation. "
            "Install it with: pip install mnemonic"
        ) from exc

    m = Mnemonic("english")
    return bool(m.check(mnemonic))


# ---------------------------------------------------------------------------
# BIP-39 seed derivation
# ---------------------------------------------------------------------------


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Derive a 64-byte BIP-39 seed from *mnemonic*.

    Uses PBKDF2-HMAC-SHA512 as specified by BIP-39::

        PBKDF2(
            password = mnemonic.encode("utf-8"),
            salt     = ("mnemonic" + passphrase).encode("utf-8"),
            rounds   = 2048,
            dklen    = 64,
        )

    This function does **not** require the ``mnemonic`` package; it operates
    solely on the raw mnemonic string.

    Parameters
    ----------
    mnemonic:
        A BIP-39 mnemonic phrase (space-separated words).
    passphrase:
        Optional passphrase to mix into the seed derivation.  Defaults to
        the empty string.

    Returns
    -------
    bytes
        A 64-byte seed suitable for use with :func:`derive_key`.
    """
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"),
        iterations=2048,
        dklen=64,
    )


# ---------------------------------------------------------------------------
# SLIP-0010 key derivation
# ---------------------------------------------------------------------------

_SLIP0010_ED25519_KEY: bytes = b"ed25519 seed"


def derive_key(seed: bytes, path: str = DEFAULT_PATH) -> bytes:
    """
    Derive a 32-byte Ed25519 private key from *seed* using SLIP-0010.

    The derivation follows the SLIP-0010 specification for Ed25519 keys:

    1. **Master key**:
       ``I = HMAC-SHA512(key=b"ed25519 seed", data=seed)``
       The master key is ``I[:32]`` and the chain code is ``I[32:]``.

    2. **Child key derivation** (hardened only for Ed25519):
       For each path segment ``i`` (with the hardened bit set):
       ``I = HMAC-SHA512(key=chain_code, data=b"\\x00" || key || (i | 0x80000000).to_bytes(4, "big"))``
       The child key is ``I[:32]`` and the child chain code is ``I[32:]``.

    Parameters
    ----------
    seed:
        A 64-byte BIP-39 seed, typically obtained from :func:`mnemonic_to_seed`.
    path:
        A BIP-44 derivation path string such as ``"m/44'/637'/0'/0'/0'"``.
        All segments must be hardened (ending in ``"'"``).  Defaults to the
        standard Aptos path :data:`DEFAULT_PATH`.

    Returns
    -------
    bytes
        A 32-byte Ed25519 private key.

    Raises
    ------
    InvalidInputError
        If *path* does not start with ``"m"``, contains non-hardened segments
        (not allowed for Ed25519), or has an invalid segment index.
    """
    # ----------------------------------------------------------------
    # Parse path
    # ----------------------------------------------------------------
    segments = path.split("/")
    if not segments or segments[0] != "m":
        raise InvalidInputError(f"Derivation path must start with 'm', got: {path!r}")

    # Validate and extract integer indices (all must be hardened for Ed25519).
    indices: list[int] = []
    for segment in segments[1:]:
        if not segment.endswith("'"):
            raise InvalidInputError(
                f"Ed25519 SLIP-0010 only supports hardened derivation. "
                f"Non-hardened path segment {segment!r} is not allowed."
            )
        try:
            index = int(segment.rstrip("'"))
        except ValueError as exc:
            raise InvalidInputError(
                f"Invalid path segment {segment!r}: index must be a non-negative integer."
            ) from exc
        if index < 0:
            raise InvalidInputError(
                f"Path segment index must be non-negative, got {index} in {segment!r}."
            )
        indices.append(index)

    # ----------------------------------------------------------------
    # Master key derivation (SLIP-0010 §3)
    # ----------------------------------------------------------------
    hmac_out = hmac.new(_SLIP0010_ED25519_KEY, seed, hashlib.sha512).digest()
    key: bytes = hmac_out[:32]
    chain_code: bytes = hmac_out[32:]

    # ----------------------------------------------------------------
    # Child key derivation — hardened only
    # ----------------------------------------------------------------
    for index in indices:
        hardened_index = index | 0x80000000
        data = b"\x00" + key + hardened_index.to_bytes(4, "big")
        hmac_out = hmac.new(chain_code, data, hashlib.sha512).digest()
        key = hmac_out[:32]
        chain_code = hmac_out[32:]

    return key
