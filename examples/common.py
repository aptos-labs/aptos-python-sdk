# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import os
import os.path

from aptos_sdk.async_client import ClientConfig

APTOS_CORE_PATH = os.getenv(
    "APTOS_CORE_PATH",
    os.path.abspath("./aptos-core"),
)
# :!:>section_1
FAUCET_URL = os.getenv(
    "APTOS_FAUCET_URL",
    "https://faucet.devnet.aptoslabs.com",
)
FAUCET_AUTH_TOKEN = os.getenv("FAUCET_AUTH_TOKEN")
INDEXER_URL = os.getenv(
    "APTOS_INDEXER_URL",
    "https://api.devnet.aptoslabs.com/v1/graphql",
)
NODE_URL = os.getenv("APTOS_NODE_URL", "https://api.devnet.aptoslabs.com/v1")

API_KEY = os.getenv("API_KEY")
# <:!:section_1

# Shared client config for examples. Uses a lower max_gas_amount than the SDK
# default (1,000,000) because faucet-funded accounts on devnet receive at most
# ~100,000,000 octas per request, and a max_gas_amount of 1,000,000 at the
# default gas_unit_price of 100 would reserve 100,000,000 octas per transaction,
# leaving no room for multiple transactions.
CLIENT_CONFIG = ClientConfig(api_key=API_KEY, max_gas_amount=100_000)
