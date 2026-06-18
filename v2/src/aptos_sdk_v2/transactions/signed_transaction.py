"""SignedTransaction — a transaction with its authenticator, ready for submission."""

from __future__ import annotations

import hashlib

from ..bcs import Deserializer, Serializer
from .authenticator import (
    AccountAuthenticator,
    Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
    SingleSenderAuthenticator,
)
from .raw_transaction import (
    FeePayerRawTransaction,
    MultiAgentRawTransaction,
    RawTransaction,
)

_TRANSACTION_PREHASH: bytes = hashlib.sha3_256(b"APTOS::Transaction").digest()
_USER_TRANSACTION_VARIANT: int = 0


class SignedTransaction:
    """A signed transaction ready for submission to the Aptos blockchain."""

    __slots__ = ("transaction", "authenticator")

    def __init__(
        self,
        transaction: RawTransaction,
        authenticator: AccountAuthenticator | Authenticator,
    ) -> None:
        self.transaction = transaction
        if isinstance(authenticator, AccountAuthenticator):
            if authenticator.variant == AccountAuthenticator.ED25519:
                authenticator = Authenticator(authenticator.authenticator)  # type: ignore[arg-type]
            else:
                authenticator = Authenticator(SingleSenderAuthenticator(authenticator))
        self.authenticator = authenticator

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignedTransaction):
            return NotImplemented
        return self.transaction == other.transaction and self.authenticator == other.authenticator

    def to_bytes(self) -> bytes:
        ser = Serializer()
        self.serialize(ser)
        return ser.output()

    def hash(self) -> str:
        """Return the committed transaction hash without submitting to the network."""
        digest = hashlib.sha3_256(
            _TRANSACTION_PREHASH + bytes([_USER_TRANSACTION_VARIANT]) + self.to_bytes()
        ).hexdigest()
        return f"0x{digest}"

    def verify(self) -> bool:
        auth = self.authenticator.authenticator
        if isinstance(auth, MultiAgentAuthenticator):
            txn = MultiAgentRawTransaction(self.transaction, auth.secondary_addresses())
            return self.authenticator.verify(txn.keyed())
        elif isinstance(auth, FeePayerAuthenticator):
            txn_fp = FeePayerRawTransaction(
                self.transaction, auth.secondary_addresses(), auth.fee_payer_address()
            )
            return self.authenticator.verify(txn_fp.keyed())
        else:
            return self.authenticator.verify(self.transaction.keyed())

    @classmethod
    def deserialize(cls, deserializer: Deserializer) -> SignedTransaction:
        transaction = RawTransaction.deserialize(deserializer)
        authenticator = Authenticator.deserialize(deserializer)
        return cls(transaction, authenticator)

    def serialize(self, serializer: Serializer) -> None:
        self.transaction.serialize(serializer)
        self.authenticator.serialize(serializer)
