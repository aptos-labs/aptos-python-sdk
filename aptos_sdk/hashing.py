# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Hashing utilities for the Aptos Python SDK (Spec 03).

This module provides:

* :func:`sha3_256` — SHA3-256 digest (the primary hash function used by Aptos).
* :func:`sha2_256` — SHA2-256 (SHA-256) digest, used for BIP-39 seed derivation.
* :class:`HashPrefix` — Pre-computed, domain-separated hash prefixes for signing
  messages.  Using a unique domain prefix for each logical message type prevents
  cross-protocol signature reuse attacks.

Domain-separated hashing
------------------------
The Aptos signing scheme prefixes every message with a fixed 32-byte tag before
hashing, following the pattern described in Spec 03::

    signing_bytes = SHA3-256("APTOS::<Domain>") || BCS(message)

All prefix constants are computed **once at module load time** to avoid
redundant hashing on the hot path.

Usage example::

    from aptos_sdk.hashing import HashPrefix, sha3_256

    # Compute a signing message for a RawTransaction
    prefix = HashPrefix.RAW_TRANSACTION          # bytes
    bcs_bytes = ...                               # BCS-encoded RawTransaction
    signing_bytes = prefix + bcs_bytes
    digest = sha3_256(signing_bytes)
"""

import hashlib

# ---------------------------------------------------------------------------
# Primitive hash functions
# ---------------------------------------------------------------------------


def sha3_256(data: bytes) -> bytes:
    """
    Return the SHA3-256 digest of *data*.

    This is the primary hash function used throughout the Aptos protocol for
    address derivation, transaction signing messages, and authentication keys.

    Parameters
    ----------
    data:
        Raw bytes to hash.

    Returns
    -------
    bytes
        32-byte SHA3-256 digest.
    """
    return hashlib.sha3_256(data).digest()


def sha2_256(data: bytes) -> bytes:
    """
    Return the SHA2-256 (SHA-256) digest of *data*.

    SHA2-256 is used in BIP-39 mnemonic checksum validation, BIP-32 / SLIP-0010
    master-key derivation (HMAC-SHA512 uses SHA-512, but checksum steps use
    SHA-256), and any Aptos sub-protocol that explicitly calls for SHA-256.

    Parameters
    ----------
    data:
        Raw bytes to hash.

    Returns
    -------
    bytes
        32-byte SHA2-256 digest.
    """
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Domain-separated hash prefixes
# ---------------------------------------------------------------------------


class HashPrefix:
    """
    Pre-computed domain-separated hash prefixes for Aptos signing messages.

    Each constant is the 32-byte SHA3-256 digest of the corresponding
    ``b"APTOS::<Domain>"`` byte string, computed once at module import time.

    Constants
    ---------
    RAW_TRANSACTION : bytes
        ``SHA3-256(b"APTOS::RawTransaction")``
        Prefix for single-signer and fee-payer transaction signing messages.
    RAW_TRANSACTION_WITH_DATA : bytes
        ``SHA3-256(b"APTOS::RawTransactionWithData")``
        Prefix for multi-agent and fee-payer transaction signing messages that
        carry additional signer data alongside the raw transaction.

    Class Methods
    -------------
    prefix_for(domain)
        Compute a domain-separated prefix on demand for arbitrary domain names.
    """

    # Pre-computed at module load time — never recompute on the hot path.
    RAW_TRANSACTION: bytes = sha3_256(b"APTOS::RawTransaction")
    RAW_TRANSACTION_WITH_DATA: bytes = sha3_256(b"APTOS::RawTransactionWithData")

    @staticmethod
    def prefix_for(domain: str) -> bytes:
        """
        Compute a domain-separated hash prefix for an arbitrary domain name.

        The returned bytes are ``SHA3-256(b"APTOS::" + domain.encode("utf-8"))``.
        This method is provided for extensibility; prefer the named class
        constants (``RAW_TRANSACTION``, etc.) for known domains, as they avoid
        recomputing the hash each call.

        Parameters
        ----------
        domain:
            Domain name without the ``"APTOS::"`` prefix, e.g. ``"MyDomain"``.
            Must be a non-empty ASCII / UTF-8 string.

        Returns
        -------
        bytes
            32-byte SHA3-256 domain prefix.

        Examples
        --------
        >>> HashPrefix.prefix_for("RawTransaction") == HashPrefix.RAW_TRANSACTION
        True
        >>> HashPrefix.prefix_for("MyCustomDomain")
        b'...'  # 32 bytes
        """
        return sha3_256(f"APTOS::{domain}".encode("utf-8"))
