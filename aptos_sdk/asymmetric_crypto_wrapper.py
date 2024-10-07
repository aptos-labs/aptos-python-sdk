# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import List, Tuple, cast

from . import asymmetric_crypto, ed25519, secp256k1_ecdsa
from .bcs import Deserializer, Serializer


class PublicKey(asymmetric_crypto.PublicKey):
    ED25519: int = 0
    SECP256K1_ECDSA: int = 1

    variant: int
    public_key: asymmetric_crypto.PublicKey

    def __init__(self, public_key: asymmetric_crypto.PublicKey):
        if isinstance(public_key, ed25519.PublicKey):
            self.variant = PublicKey.ED25519
        elif isinstance(public_key, secp256k1_ecdsa.PublicKey):
            self.variant = PublicKey.SECP256K1_ECDSA
        else:
            raise NotImplementedError()
        self.public_key = public_key

    def to_crypto_bytes(self) -> bytes:
        ser = Serializer()
        self.serialize(ser)
        return ser.output()

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        # Convert signature to the original signature
        sig = cast(Signature, signature)

        return self.public_key.verify(data, sig.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PublicKey:
        variant = deserializer.uleb128()

        if variant == PublicKey.ED25519:
            public_key: asymmetric_crypto.PublicKey = ed25519.PublicKey.deserialize(
                deserializer
            )
        elif variant == Signature.SECP256K1_ECDSA:
            public_key = secp256k1_ecdsa.PublicKey.deserialize(deserializer)
        else:
            raise Exception(f"Invalid type: {variant}")

        return PublicKey(public_key)

    def serialize(self, serializer: Serializer):
        serializer.uleb128(self.variant)
        serializer.struct(self.public_key)


class Signature(asymmetric_crypto.Signature):
    ED25519: int = 0
    SECP256K1_ECDSA: int = 1

    variant: int
    signature: asymmetric_crypto.Signature

    def __init__(self, signature: asymmetric_crypto.Signature):
        if isinstance(signature, ed25519.Signature):
            self.variant = Signature.ED25519
        elif isinstance(signature, secp256k1_ecdsa.Signature):
            self.variant = Signature.SECP256K1_ECDSA
        else:
            raise NotImplementedError()
        self.signature = signature

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Signature:
        variant = deserializer.uleb128()

        if variant == Signature.ED25519:
            signature: asymmetric_crypto.Signature = ed25519.Signature.deserialize(
                deserializer
            )
        elif variant == Signature.SECP256K1_ECDSA:
            signature = secp256k1_ecdsa.Signature.deserialize(deserializer)
        else:
            raise Exception(f"Invalid type: {variant}")

        return Signature(signature)

    def serialize(self, serializer: Serializer):
        serializer.uleb128(self.variant)
        serializer.struct(self.signature)


class MultiPublicKey(asymmetric_crypto.PublicKey):
    keys: List[PublicKey]
    threshold: int

    MIN_KEYS = 2
    MAX_KEYS = 32
    MIN_THRESHOLD = 1

    def __init__(self, keys: List[asymmetric_crypto.PublicKey], threshold: int):
        assert (
            self.MIN_KEYS <= len(keys) <= self.MAX_KEYS
        ), f"Must have between {self.MIN_KEYS} and {self.MAX_KEYS} keys."
        assert (
            self.MIN_THRESHOLD <= threshold <= len(keys)
        ), f"Threshold must be between {self.MIN_THRESHOLD} and {len(keys)}."

        # Ensure keys are wrapped
        self.keys = []
        for key in keys:
            if isinstance(key, PublicKey):
                self.keys.append(key)
            else:
                self.keys.append(PublicKey(key))

        self.threshold = threshold

    def __str__(self) -> str:
        return f"{self.threshold}-of-{len(self.keys)} Multi key"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            total_sig = cast(MultiSignature, signature)
            assert self.threshold <= len(
                total_sig.signatures
            ), f"Insufficient signatures, {self.threshold} > {len(total_sig.signatures)}"

            for idx, signature in total_sig.signatures:
                assert (
                    len(self.keys) > idx
                ), f"Signature index exceeds available keys {len(self.keys)} < {idx}"
                assert self.keys[idx].verify(
                    data, signature
                ), "Unable to verify signature"

        except Exception:
            return False
        return True

    @staticmethod
    def from_crypto_bytes(indata: bytes) -> MultiPublicKey:
        deserializer = Deserializer(indata)
        return deserializer.struct(MultiPublicKey)

    def to_crypto_bytes(self) -> bytes:
        serializer = Serializer()
        serializer.struct(self)
        return serializer.output()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiPublicKey:
        keys = deserializer.sequence(PublicKey.deserialize)
        threshold = deserializer.u8()
        return MultiPublicKey(keys, threshold)

    def serialize(self, serializer: Serializer):
        serializer.sequence(self.keys, Serializer.struct)
        serializer.u8(self.threshold)


class MultiSignature(asymmetric_crypto.Signature):
    signatures: List[Tuple[int, Signature]]
    MAX_SIGNATURES: int = 16

    def __init__(self, signatures: List[Tuple[int, asymmetric_crypto.Signature]]):
        # Sort first to ensure no issues in order
        # signatures.sort(key=lambda x: x[0])
        self.signatures = []
        for index, signature in signatures:
            assert index < self.MAX_SIGNATURES, "bitmap value exceeds maximum value"
            if isinstance(signature, Signature):
                self.signatures.append((index, signature))
            else:
                self.signatures.append((index, Signature(signature)))

    def __eq__(self, other: object):
        if not isinstance(other, MultiSignature):
            return NotImplemented
        return self.signatures == other.signatures

    def __str__(self) -> str:
        return f"{self.signatures}"

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiSignature:
        signatures = deserializer.sequence(Signature.deserialize)
        bitmap_raw = deserializer.to_bytes()
        bitmap = int.from_bytes(bitmap_raw, "little")
        num_bits = len(bitmap_raw) * 8
        sig_index = 0
        indexed_signatures = []

        for i in range(0, num_bits):
            has_signature = (bitmap & index_to_bitmap_value(i)) != 0
            if has_signature:
                indexed_signatures.append((i, signatures[sig_index]))
                sig_index += 1

        return MultiSignature(indexed_signatures)

    def serialize(self, serializer: Serializer):
        actual_sigs = []
        bitmap = 0

        for i, signature in self.signatures:
            bitmap |= index_to_bitmap_value(i)
            actual_sigs.append(signature)

        serializer.sequence(actual_sigs, Serializer.struct)
        count = 1 if bitmap < 256 else 2
        serializer.to_bytes(bitmap.to_bytes(count, "little"))


def index_to_bitmap_value(i: int) -> int:
    bit = i % 8
    byte = i // 8
    return (128 >> bit) << (byte * 8)
