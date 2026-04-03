"""Transaction authenticator types for signature verification."""

from __future__ import annotations

from typing import Any

from ..bcs import Deserializer, Serializer
from ..crypto.ed25519 import Ed25519PublicKey, Ed25519Signature
from ..crypto.single_key import AnyPublicKey, AnySignature
from ..errors import BcsDeserializationError
from ..types.account_address import AccountAddress

# --- Account-level authenticators ---


class Ed25519Authenticator:
    """Single Ed25519 key + signature pair."""

    __slots__ = ("public_key", "signature")

    def __init__(
        self, public_key: Ed25519PublicKey, signature: Ed25519Signature
    ) -> None:
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519Authenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def verify(self, data: bytes) -> bool:
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Ed25519Authenticator:
        key = deserializer.struct(Ed25519PublicKey)
        sig = deserializer.struct(Ed25519Signature)
        return Ed25519Authenticator(key, sig)

    def serialize(self, serializer: Serializer) -> None:
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class SingleKeyAuthenticator:
    """Generic single-key authenticator (wraps Secp256k1 and other non-Ed25519 keys)."""

    __slots__ = ("public_key", "signature")

    def __init__(self, public_key: Any, signature: Any) -> None:
        self.public_key = (
            public_key
            if isinstance(public_key, AnyPublicKey)
            else AnyPublicKey(public_key)
        )
        self.signature = (
            signature
            if isinstance(signature, AnySignature)
            else AnySignature(signature)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SingleKeyAuthenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def verify(self, data: bytes) -> bool:
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> SingleKeyAuthenticator:
        pub = deserializer.struct(AnyPublicKey)
        sig = deserializer.struct(AnySignature)
        return SingleKeyAuthenticator(pub, sig)

    def serialize(self, serializer: Serializer) -> None:
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class SingleSenderAuthenticator:
    """Wrapper for a single sender's AccountAuthenticator."""

    __slots__ = ("sender",)

    def __init__(self, sender: AccountAuthenticator) -> None:
        self.sender = sender

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SingleSenderAuthenticator):
            return NotImplemented
        return self.sender == other.sender

    def verify(self, data: bytes) -> bool:
        return self.sender.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> SingleSenderAuthenticator:
        sender = deserializer.struct(AccountAuthenticator)
        return SingleSenderAuthenticator(sender)

    def serialize(self, serializer: Serializer) -> None:
        serializer.struct(self.sender)


class MultiAgentAuthenticator:
    """Multi-agent authenticator: sender + secondary signers."""

    __slots__ = ("sender", "secondary_signers")

    def __init__(
        self,
        sender: AccountAuthenticator,
        secondary_signers: list[tuple[AccountAddress, AccountAuthenticator]],
    ) -> None:
        self.sender = sender
        self.secondary_signers = secondary_signers

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiAgentAuthenticator):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.secondary_signers == other.secondary_signers
        )

    def secondary_addresses(self) -> list[AccountAddress]:
        return [addr for addr, _ in self.secondary_signers]

    def verify(self, data: bytes) -> bool:
        if not self.sender.verify(data):
            return False
        return all(auth.verify(data) for _, auth in self.secondary_signers)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiAgentAuthenticator:
        sender = deserializer.struct(AccountAuthenticator)
        addresses = deserializer.sequence(AccountAddress.deserialize)
        authenticators = deserializer.sequence(AccountAuthenticator.deserialize)
        return MultiAgentAuthenticator(sender, list(zip(addresses, authenticators)))

    def serialize(self, serializer: Serializer) -> None:
        serializer.struct(self.sender)
        serializer.sequence(
            [addr for addr, _ in self.secondary_signers], Serializer.struct
        )
        serializer.sequence(
            [auth for _, auth in self.secondary_signers], Serializer.struct
        )


class FeePayerAuthenticator:
    """Fee-payer authenticator: sender + secondary signers + fee payer."""

    __slots__ = ("sender", "secondary_signers", "fee_payer")

    def __init__(
        self,
        sender: AccountAuthenticator,
        secondary_signers: list[tuple[AccountAddress, AccountAuthenticator]],
        fee_payer: tuple[AccountAddress, AccountAuthenticator],
    ) -> None:
        self.sender = sender
        self.secondary_signers = secondary_signers
        self.fee_payer = fee_payer

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FeePayerAuthenticator):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.secondary_signers == other.secondary_signers
            and self.fee_payer == other.fee_payer
        )

    def fee_payer_address(self) -> AccountAddress:
        return self.fee_payer[0]

    def secondary_addresses(self) -> list[AccountAddress]:
        return [addr for addr, _ in self.secondary_signers]

    def verify(self, data: bytes) -> bool:
        if not self.sender.verify(data):
            return False
        if not self.fee_payer[1].verify(data):
            return False
        return all(auth.verify(data) for _, auth in self.secondary_signers)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> FeePayerAuthenticator:
        sender = deserializer.struct(AccountAuthenticator)
        addresses = deserializer.sequence(AccountAddress.deserialize)
        authenticators = deserializer.sequence(AccountAuthenticator.deserialize)
        fee_payer_addr = deserializer.struct(AccountAddress)
        fee_payer_auth = deserializer.struct(AccountAuthenticator)
        return FeePayerAuthenticator(
            sender,
            list(zip(addresses, authenticators)),
            (fee_payer_addr, fee_payer_auth),
        )

    def serialize(self, serializer: Serializer) -> None:
        serializer.struct(self.sender)
        serializer.sequence(
            [addr for addr, _ in self.secondary_signers], Serializer.struct
        )
        serializer.sequence(
            [auth for _, auth in self.secondary_signers], Serializer.struct
        )
        serializer.struct(self.fee_payer[0])
        serializer.struct(self.fee_payer[1])


# --- Variant wrappers ---


class AccountAuthenticator:
    """Single account's authentication variant."""

    ED25519 = 0
    MULTI_ED25519 = 1
    SINGLE_KEY = 2
    MULTI_KEY = 3

    __slots__ = ("variant", "authenticator")

    def __init__(
        self, authenticator: Ed25519Authenticator | SingleKeyAuthenticator
    ) -> None:
        if isinstance(authenticator, Ed25519Authenticator):
            self.variant = AccountAuthenticator.ED25519
        elif isinstance(authenticator, SingleKeyAuthenticator):
            self.variant = AccountAuthenticator.SINGLE_KEY
        else:
            raise TypeError(
                f"Invalid authenticator type: {type(authenticator).__name__}"
            )
        self.authenticator = authenticator

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AccountAuthenticator):
            return NotImplemented
        return (
            self.variant == other.variant and self.authenticator == other.authenticator
        )

    def verify(self, data: bytes) -> bool:
        return self.authenticator.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AccountAuthenticator:
        variant = deserializer.uleb128()
        match variant:
            case AccountAuthenticator.ED25519:
                return AccountAuthenticator(
                    Ed25519Authenticator.deserialize(deserializer)
                )
            case AccountAuthenticator.SINGLE_KEY:
                return AccountAuthenticator(
                    SingleKeyAuthenticator.deserialize(deserializer)
                )
            case _:
                raise BcsDeserializationError(
                    f"Unknown AccountAuthenticator variant: {variant}"
                )

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.variant)
        serializer.struct(self.authenticator)


class Authenticator:
    """Top-level transaction authenticator."""

    ED25519 = 0
    MULTI_ED25519 = 1
    MULTI_AGENT = 2
    FEE_PAYER = 3
    SINGLE_SENDER = 4

    __slots__ = ("variant", "authenticator")

    def __init__(
        self,
        authenticator: (
            Ed25519Authenticator
            | MultiAgentAuthenticator
            | FeePayerAuthenticator
            | SingleSenderAuthenticator
        ),
    ) -> None:
        if isinstance(authenticator, Ed25519Authenticator):
            self.variant = Authenticator.ED25519
        elif isinstance(authenticator, MultiAgentAuthenticator):
            self.variant = Authenticator.MULTI_AGENT
        elif isinstance(authenticator, FeePayerAuthenticator):
            self.variant = Authenticator.FEE_PAYER
        elif isinstance(authenticator, SingleSenderAuthenticator):
            self.variant = Authenticator.SINGLE_SENDER
        else:
            raise TypeError(
                f"Invalid authenticator type: {type(authenticator).__name__}"
            )
        self.authenticator = authenticator

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Authenticator):
            return NotImplemented
        return (
            self.variant == other.variant and self.authenticator == other.authenticator
        )

    def verify(self, data: bytes) -> bool:
        return self.authenticator.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Authenticator:
        variant = deserializer.uleb128()
        match variant:
            case Authenticator.ED25519:
                return Authenticator(Ed25519Authenticator.deserialize(deserializer))
            case Authenticator.MULTI_AGENT:
                return Authenticator(MultiAgentAuthenticator.deserialize(deserializer))
            case Authenticator.FEE_PAYER:
                return Authenticator(FeePayerAuthenticator.deserialize(deserializer))
            case Authenticator.SINGLE_SENDER:
                return Authenticator(
                    SingleSenderAuthenticator.deserialize(deserializer)
                )
            case _:
                raise BcsDeserializationError(
                    f"Unknown Authenticator variant: {variant}"
                )

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.variant)
        serializer.struct(self.authenticator)
