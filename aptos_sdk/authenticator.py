# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing
import unittest
from typing import List

from . import asymmetric_crypto, asymmetric_crypto_wrapper, ed25519, secp256k1_ecdsa
from .account_address import AccountAddress
from .bcs import Deserializer, Serializer


class Authenticator:
    """
    Each transaction submitted to the Aptos blockchain contains a `TransactionAuthenticator`.
    During transaction execution, the executor will check if every `AccountAuthenticator`'s
    signature on the transaction hash is well-formed and whether `AccountAuthenticator`'s  matches
    the `AuthenticationKey` stored under the participating signer's account address.
    """

    ED25519: int = 0
    MULTI_ED25519: int = 1
    MULTI_AGENT: int = 2
    FEE_PAYER: int = 3
    SINGLE_SENDER: int = 4

    variant: int
    authenticator: typing.Any

    def __init__(self, authenticator: typing.Any):
        if isinstance(authenticator, Ed25519Authenticator):
            self.variant = Authenticator.ED25519
        elif isinstance(authenticator, MultiEd25519Authenticator):
            self.variant = Authenticator.MULTI_ED25519
        elif isinstance(authenticator, MultiAgentAuthenticator):
            self.variant = Authenticator.MULTI_AGENT
        elif isinstance(authenticator, FeePayerAuthenticator):
            self.variant = Authenticator.FEE_PAYER
        elif isinstance(authenticator, SingleSenderAuthenticator):
            self.variant = Authenticator.SINGLE_SENDER
        else:
            raise Exception("Invalid type")
        self.authenticator = authenticator

    def from_key(key: asymmetric_crypto.PublicKey) -> int:
        if isinstance(key, ed25519.PublicKey):
            return Authenticator.ED25519
        elif isinstance(key, ed25519.MultiPublicKey):
            return Authenticator.MULTI_ED25519
        else:
            raise NotImplementedError()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Authenticator):
            return NotImplemented
        return (
            self.variant == other.variant and self.authenticator == other.authenticator
        )

    def __str__(self) -> str:
        return self.authenticator.__str__()

    def verify(self, data: bytes) -> bool:
        return self.authenticator.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Authenticator:
        variant = deserializer.uleb128()

        if variant == Authenticator.ED25519:
            authenticator: typing.Any = Ed25519Authenticator.deserialize(deserializer)
        elif variant == Authenticator.MULTI_ED25519:
            authenticator = MultiEd25519Authenticator.deserialize(deserializer)
        elif variant == Authenticator.MULTI_AGENT:
            authenticator = MultiAgentAuthenticator.deserialize(deserializer)
        elif variant == Authenticator.FEE_PAYER:
            authenticator = FeePayerAuthenticator.deserialize(deserializer)
        elif variant == Authenticator.SINGLE_SENDER:
            authenticator = SingleSenderAuthenticator.deserialize(deserializer)
        else:
            raise Exception(f"Invalid type: {variant}")

        return Authenticator(authenticator)

    def serialize(self, serializer: Serializer):
        serializer.uleb128(self.variant)
        serializer.struct(self.authenticator)


class AccountAuthenticator:
    ED25519: int = 0
    MULTI_ED25519: int = 1
    SINGLE_KEY: int = 2
    MULTI_KEY: int = 3

    variant: int
    authenticator: typing.Any

    def __init__(self, authenticator: typing.Any):
        if isinstance(authenticator, Ed25519Authenticator):
            self.variant = AccountAuthenticator.ED25519
        elif isinstance(authenticator, MultiEd25519Authenticator):
            self.variant = AccountAuthenticator.MULTI_ED25519
        elif isinstance(authenticator, SingleKeyAuthenticator):
            self.variant = AccountAuthenticator.SINGLE_KEY
        elif isinstance(authenticator, MultiKeyAuthenticator):
            self.variant = AccountAuthenticator.MULTI_KEY
        else:
            raise Exception("Invalid type")
        self.authenticator = authenticator

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AccountAuthenticator):
            return NotImplemented
        return (
            self.variant == other.variant and self.authenticator == other.authenticator
        )

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return self.authenticator.__str__()

    def verify(self, data: bytes) -> bool:
        return self.authenticator.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AccountAuthenticator:
        variant = deserializer.uleb128()

        if variant == AccountAuthenticator.ED25519:
            authenticator: typing.Any = Ed25519Authenticator.deserialize(deserializer)
        elif variant == AccountAuthenticator.MULTI_ED25519:
            authenticator = MultiEd25519Authenticator.deserialize(deserializer)
        elif variant == AccountAuthenticator.SINGLE_KEY:
            authenticator = SingleKeyAuthenticator.deserialize(deserializer)
        elif variant == AccountAuthenticator.MULTI_KEY:
            authenticator = MultiKeyAuthenticator.deserialize(deserializer)
        else:
            raise Exception(f"Invalid type: {variant}")

        return AccountAuthenticator(authenticator)

    def serialize(self, serializer: Serializer):
        serializer.uleb128(self.variant)
        serializer.struct(self.authenticator)


class Ed25519Authenticator:
    public_key: ed25519.PublicKey
    signature: ed25519.Signature

    def __init__(self, public_key: ed25519.PublicKey, signature: ed25519.Signature):
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519Authenticator):
            return NotImplemented

        return self.public_key == other.public_key and self.signature == other.signature

    def __str__(self) -> str:
        return f"PublicKey: {self.public_key}, Signature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Ed25519Authenticator:
        key = deserializer.struct(ed25519.PublicKey)
        signature = deserializer.struct(ed25519.Signature)
        return Ed25519Authenticator(key, signature)

    def serialize(self, serializer: Serializer):
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class FeePayerAuthenticator:
    sender: AccountAuthenticator
    secondary_signers: List[typing.Tuple[AccountAddress, AccountAuthenticator]]
    fee_payer: typing.Tuple[AccountAddress, AccountAuthenticator]

    def __init__(
        self,
        sender: AccountAuthenticator,
        secondary_signers: List[typing.Tuple[AccountAddress, AccountAuthenticator]],
        fee_payer: typing.Tuple[AccountAddress, AccountAuthenticator],
    ):
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

    def __str__(self) -> str:
        return f"FeePayer: \n\tSender: {self.sender}\n\tSecondary Signers: {self.secondary_signers}\n\t{self.fee_payer}"

    def fee_payer_address(self) -> AccountAddress:
        return self.fee_payer[0]

    def secondary_addresses(self) -> List[AccountAddress]:
        return [x[0] for x in self.secondary_signers]

    def verify(self, data: bytes) -> bool:
        if not self.sender.verify(data):
            return False
        if not self.fee_payer[1].verify(data):
            return False
        return all([x[1].verify(data) for x in self.secondary_signers])

    @staticmethod
    def deserialize(deserializer: Deserializer) -> FeePayerAuthenticator:
        sender = deserializer.struct(AccountAuthenticator)
        secondary_addresses = deserializer.sequence(AccountAddress.deserialize)
        secondary_authenticators = deserializer.sequence(
            AccountAuthenticator.deserialize
        )
        fee_payer_address = deserializer.struct(AccountAddress)
        fee_payer_authenticator = deserializer.struct(AccountAuthenticator)
        return FeePayerAuthenticator(
            sender,
            list(zip(secondary_addresses, secondary_authenticators)),
            (fee_payer_address, fee_payer_authenticator),
        )

    def serialize(self, serializer: Serializer):
        serializer.struct(self.sender)
        serializer.sequence([x[0] for x in self.secondary_signers], Serializer.struct)
        serializer.sequence([x[1] for x in self.secondary_signers], Serializer.struct)
        serializer.struct(self.fee_payer[0])
        serializer.struct(self.fee_payer[1])


class MultiAgentAuthenticator:
    sender: AccountAuthenticator
    secondary_signers: List[typing.Tuple[AccountAddress, AccountAuthenticator]]

    def __init__(
        self,
        sender: AccountAuthenticator,
        secondary_signers: List[typing.Tuple[AccountAddress, AccountAuthenticator]],
    ):
        self.sender = sender
        self.secondary_signers = secondary_signers

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiAgentAuthenticator):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.secondary_signers == other.secondary_signers
        )

    def secondary_addresses(self) -> List[AccountAddress]:
        return [x[0] for x in self.secondary_signers]

    def verify(self, data: bytes) -> bool:
        if not self.sender.verify(data):
            return False
        return all([x[1].verify(data) for x in self.secondary_signers])

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiAgentAuthenticator:
        sender = deserializer.struct(AccountAuthenticator)
        secondary_addresses = deserializer.sequence(AccountAddress.deserialize)
        secondary_authenticators = deserializer.sequence(
            AccountAuthenticator.deserialize
        )
        return MultiAgentAuthenticator(
            sender, list(zip(secondary_addresses, secondary_authenticators))
        )

    def serialize(self, serializer: Serializer):
        serializer.struct(self.sender)
        serializer.sequence([x[0] for x in self.secondary_signers], Serializer.struct)
        serializer.sequence([x[1] for x in self.secondary_signers], Serializer.struct)


class MultiEd25519Authenticator:
    public_key: ed25519.MultiPublicKey
    signature: ed25519.MultiSignature

    def __init__(self, public_key, signature):
        self.public_key = public_key
        self.signature = signature

    def verify(self, data: bytes) -> bool:
        raise NotImplementedError

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiEd25519Authenticator:
        raise NotImplementedError

    def serialize(self, serializer: Serializer):
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class SingleSenderAuthenticator:
    sender: AccountAuthenticator

    def __init__(
        self,
        sender: AccountAuthenticator,
    ):
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

    def serialize(self, serializer: Serializer):
        serializer.struct(self.sender)


class SingleKeyAuthenticator:
    public_key: asymmetric_crypto_wrapper.PublicKey
    signature: asymmetric_crypto_wrapper.Signature

    def __init__(
        self,
        public_key: asymmetric_crypto.PublicKey,
        signature: asymmetric_crypto.Signature,
    ):
        if isinstance(public_key, asymmetric_crypto_wrapper.PublicKey):
            self.public_key = public_key
        else:
            self.public_key = asymmetric_crypto_wrapper.PublicKey(public_key)

        if isinstance(signature, asymmetric_crypto_wrapper.Signature):
            self.signature = signature
        else:
            self.signature = asymmetric_crypto_wrapper.Signature(signature)

    def verify(self, data: bytes) -> bool:
        return self.public_key.verify(data, self.signature.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> SingleKeyAuthenticator:
        public_key = deserializer.struct(asymmetric_crypto_wrapper.PublicKey)
        signature = deserializer.struct(asymmetric_crypto_wrapper.Signature)
        return SingleKeyAuthenticator(public_key, signature)

    def serialize(self, serializer: Serializer):
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class MultiKeyAuthenticator:
    public_key: asymmetric_crypto_wrapper.MultiPublicKey
    signature: asymmetric_crypto_wrapper.MultiSignature

    def __init__(
        self,
        public_key: asymmetric_crypto_wrapper.MultiPublicKey,
        signature: asymmetric_crypto_wrapper.MultiSignature,
    ):
        self.public_key = public_key
        self.signature = signature

    def verify(self, data: bytes) -> bool:
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiKeyAuthenticator:
        public_key = deserializer.struct(asymmetric_crypto_wrapper.MultiPublicKey)
        signature = deserializer.struct(asymmetric_crypto_wrapper.MultiSignature)
        return MultiKeyAuthenticator(public_key, signature)

    def serialize(self, serializer: Serializer):
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class Test(unittest.TestCase):
    def test_multi_key_auth(self):
        expected_output = bytes.fromhex(
            "040303002020fdbac9b10b7587bba7b5bc163bce69e796d71e4ed44c10fcb4488689f7a1440141049b8327d929a0e45285c04d19c9fffbee065c266b701972922d807228120e43f34ad68ac77f6ec0205fe39f7c5b6055dad973a03464a3a743302de0feaf6ec6d90141049b8327d929a0e45285c04d19c9fffbee065c266b701972922d807228120e43f34ad68ac77f6ec0205fe39f7c5b6055dad973a03464a3a743302de0feaf6ec6d902020040a9839b56be99b48c285ec252cf9bf779e42d3b62eb8664c31b18c1fdb29b574b1bfde0b89aedddb9fb8304ca5913c9feefea75d332d8f72ac3ab4598a884ea0801402bd50683abe6332a496121f8ec7db7be351f49b0087fa0dfb258c469822bd52e59fc9344944a1f338b0f0a61c7173453e0cd09cf961e45cb9396808fa67eeef301c0"
        )
        der = Deserializer(expected_output)
        der.struct(Authenticator)

        pk0 = ed25519.PublicKey.from_str(
            "20FDBAC9B10B7587BBA7B5BC163BCE69E796D71E4ED44C10FCB4488689F7A144"
        )
        pk1 = secp256k1_ecdsa.PublicKey.from_str(
            "049B8327D929A0E45285C04D19C9FFFBEE065C266B701972922D807228120E43F34AD68AC77F6EC0205FE39F7C5B6055DAD973A03464A3A743302DE0FEAF6EC6D9"
        )
        pk2 = secp256k1_ecdsa.PublicKey.from_str(
            "049B8327D929A0E45285C04D19C9FFFBEE065C266B701972922D807228120E43F34AD68AC77F6EC0205FE39F7C5B6055DAD973A03464A3A743302DE0FEAF6EC6D9"
        )
        sig0 = ed25519.Signature.from_str(
            "a9839b56be99b48c285ec252cf9bf779e42d3b62eb8664c31b18c1fdb29b574b1bfde0b89aedddb9fb8304ca5913c9feefea75d332d8f72ac3ab4598a884ea08"
        )
        sig1 = secp256k1_ecdsa.Signature.from_str(
            "2bd50683abe6332a496121f8ec7db7be351f49b0087fa0dfb258c469822bd52e59fc9344944a1f338b0f0a61c7173453e0cd09cf961e45cb9396808fa67eeef3"
        )

        multi_key = asymmetric_crypto_wrapper.MultiPublicKey([pk0, pk1, pk2], 2)
        multi_sig = asymmetric_crypto_wrapper.MultiSignature([(0, sig0), (1, sig1)])
        multi_key_auth = MultiKeyAuthenticator(multi_key, multi_sig)
        single_sender_auth = SingleSenderAuthenticator(
            AccountAuthenticator(multi_key_auth)
        )
        txn_auth = Authenticator(single_sender_auth)
        ser = Serializer()
        txn_auth.serialize(ser)
        self.assertEqual(expected_output, ser.output())
