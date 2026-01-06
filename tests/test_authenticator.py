# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for Authenticator module.
"""

import pytest
from aptos_sdk import ed25519, secp256k1_ecdsa
from aptos_sdk import asymmetric_crypto_wrapper
from aptos_sdk.authenticator import (
    AccountAuthenticator,
    Authenticator,
    MultiKeyAuthenticator,
    SingleSenderAuthenticator,
)
from aptos_sdk.bcs import Deserializer, Serializer


class TestMultiKeyAuthenticator:
    """Tests for MultiKey authenticator."""

    def test_multi_key_auth(self):
        """Test MultiKey authenticator serialization."""
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
        assert expected_output == ser.output()

