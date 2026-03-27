"""RawTransaction and variants — the unsigned transaction types that get signed."""

from __future__ import annotations

import hashlib

from ..bcs import Deserializer, Serializer
from ..crypto.ed25519 import Ed25519PublicKey, Ed25519Signature
from ..crypto.keys import PrivateKey, PublicKey, Signature
from ..crypto.secp256k1 import Secp256k1PublicKey, Secp256k1Signature
from ..errors import BcsDeserializationError
from ..types.account_address import AccountAddress
from .authenticator import (
    AccountAuthenticator,
    Ed25519Authenticator,
    SingleKeyAuthenticator,
)
from .payload import TransactionPayload


def _raw_txn_prehash() -> bytes:
    """SHA3-256 of b"APTOS::RawTransaction" — the domain separator for single-sender signing."""
    hasher = hashlib.sha3_256()
    hasher.update(b"APTOS::RawTransaction")
    return hasher.digest()


def _raw_txn_with_data_prehash() -> bytes:
    """SHA3-256 of b"APTOS::RawTransactionWithData" — for multi-agent/fee-payer signing."""
    hasher = hashlib.sha3_256()
    hasher.update(b"APTOS::RawTransactionWithData")
    return hasher.digest()


def _sign_internal(keyed_data: bytes, key: PrivateKey) -> AccountAuthenticator:
    """Sign keyed data and return the appropriate AccountAuthenticator."""
    signature = key.sign(keyed_data)
    pub = key.public_key()
    if isinstance(pub, Ed25519PublicKey) and isinstance(signature, Ed25519Signature):
        return AccountAuthenticator(Ed25519Authenticator(pub, signature))
    return AccountAuthenticator(SingleKeyAuthenticator(pub, signature))


def _sign_simulated(keyed_data: bytes, key: PublicKey) -> AccountAuthenticator:
    """Create a zero-signature authenticator for simulation."""
    if isinstance(key, Ed25519PublicKey):
        return AccountAuthenticator(Ed25519Authenticator(key, Ed25519Signature(b"\x00" * 64)))
    elif isinstance(key, Secp256k1PublicKey):
        return AccountAuthenticator(SingleKeyAuthenticator(key, Secp256k1Signature(b"\x00" * 64)))
    raise NotImplementedError(f"Unsupported key type for simulation: {type(key).__name__}")


class RawTransaction:
    """An unsigned transaction ready to be signed."""

    __slots__ = (
        "sender",
        "sequence_number",
        "payload",
        "max_gas_amount",
        "gas_unit_price",
        "expiration_timestamps_secs",
        "chain_id",
    )

    def __init__(
        self,
        sender: AccountAddress,
        sequence_number: int,
        payload: TransactionPayload,
        max_gas_amount: int,
        gas_unit_price: int,
        expiration_timestamps_secs: int,
        chain_id: int,
    ) -> None:
        self.sender = sender
        self.sequence_number = sequence_number
        self.payload = payload
        self.max_gas_amount = max_gas_amount
        self.gas_unit_price = gas_unit_price
        self.expiration_timestamps_secs = expiration_timestamps_secs
        self.chain_id = chain_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RawTransaction):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.sequence_number == other.sequence_number
            and self.payload == other.payload
            and self.max_gas_amount == other.max_gas_amount
            and self.gas_unit_price == other.gas_unit_price
            and self.expiration_timestamps_secs == other.expiration_timestamps_secs
            and self.chain_id == other.chain_id
        )

    def keyed(self) -> bytes:
        """Produce the signing message: prehash || BCS(self)."""
        ser = Serializer()
        self.serialize(ser)
        prehash = bytearray(_raw_txn_prehash())
        prehash.extend(ser.output())
        return bytes(prehash)

    def sign(self, private_key: PrivateKey) -> AccountAuthenticator:
        return _sign_internal(self.keyed(), private_key)

    def sign_simulated(self, public_key: PublicKey) -> AccountAuthenticator:
        return _sign_simulated(self.keyed(), public_key)

    def verify(self, key: Ed25519PublicKey, signature: Signature) -> bool:
        return key.verify(self.keyed(), signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> RawTransaction:
        return RawTransaction(
            AccountAddress.deserialize(deserializer),
            deserializer.u64(),
            TransactionPayload.deserialize(deserializer),
            deserializer.u64(),
            deserializer.u64(),
            deserializer.u64(),
            deserializer.u8(),
        )

    def serialize(self, serializer: Serializer) -> None:
        self.sender.serialize(serializer)
        serializer.u64(self.sequence_number)
        self.payload.serialize(serializer)
        serializer.u64(self.max_gas_amount)
        serializer.u64(self.gas_unit_price)
        serializer.u64(self.expiration_timestamps_secs)
        serializer.u8(self.chain_id)


class MultiAgentRawTransaction:
    """A multi-agent transaction (sender + secondary signers)."""

    __slots__ = ("raw_transaction", "secondary_signers")

    def __init__(
        self, raw_transaction: RawTransaction, secondary_signers: list[AccountAddress]
    ) -> None:
        self.raw_transaction = raw_transaction
        self.secondary_signers = secondary_signers

    def inner(self) -> RawTransaction:
        return self.raw_transaction

    def keyed(self) -> bytes:
        ser = Serializer()
        self.serialize(ser)
        prehash = bytearray(_raw_txn_with_data_prehash())
        prehash.extend(ser.output())
        return bytes(prehash)

    def sign(self, private_key: PrivateKey) -> AccountAuthenticator:
        return _sign_internal(self.keyed(), private_key)

    def serialize(self, serializer: Serializer) -> None:
        serializer.u8(0)
        serializer.struct(self.raw_transaction)
        serializer.sequence(self.secondary_signers, Serializer.struct)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiAgentRawTransaction:
        tag = deserializer.u8()
        if tag != 0:
            raise BcsDeserializationError(f"Expected multi-agent tag 0, got {tag}")
        return MultiAgentRawTransaction._deserialize_inner(deserializer)

    @staticmethod
    def _deserialize_inner(deserializer: Deserializer) -> MultiAgentRawTransaction:
        raw_txn = RawTransaction.deserialize(deserializer)
        secondary = deserializer.sequence(AccountAddress.deserialize)
        return MultiAgentRawTransaction(raw_txn, secondary)


class FeePayerRawTransaction:
    """A fee-payer transaction (sender + secondary signers + fee payer)."""

    __slots__ = ("raw_transaction", "secondary_signers", "fee_payer")

    def __init__(
        self,
        raw_transaction: RawTransaction,
        secondary_signers: list[AccountAddress],
        fee_payer: AccountAddress | None,
    ) -> None:
        self.raw_transaction = raw_transaction
        self.secondary_signers = secondary_signers
        self.fee_payer = fee_payer

    def inner(self) -> RawTransaction:
        return self.raw_transaction

    def keyed(self) -> bytes:
        ser = Serializer()
        self.serialize(ser)
        prehash = bytearray(_raw_txn_with_data_prehash())
        prehash.extend(ser.output())
        return bytes(prehash)

    def sign(self, private_key: PrivateKey) -> AccountAuthenticator:
        return _sign_internal(self.keyed(), private_key)

    def serialize(self, serializer: Serializer) -> None:
        serializer.u8(1)
        serializer.struct(self.raw_transaction)
        serializer.sequence(self.secondary_signers, Serializer.struct)
        fee_payer = self.fee_payer if self.fee_payer is not None else AccountAddress.from_str("0x0")
        serializer.struct(fee_payer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> FeePayerRawTransaction:
        tag = deserializer.u8()
        if tag != 1:
            raise BcsDeserializationError(f"Expected fee-payer tag 1, got {tag}")
        return FeePayerRawTransaction._deserialize_inner(deserializer)

    @staticmethod
    def _deserialize_inner(deserializer: Deserializer) -> FeePayerRawTransaction:
        raw_txn = RawTransaction.deserialize(deserializer)
        secondary = deserializer.sequence(AccountAddress.deserialize)
        fee_payer_addr = AccountAddress.deserialize(deserializer)
        if fee_payer_addr == AccountAddress.from_str("0x0"):
            return FeePayerRawTransaction(raw_txn, secondary, None)
        return FeePayerRawTransaction(raw_txn, secondary, fee_payer_addr)
