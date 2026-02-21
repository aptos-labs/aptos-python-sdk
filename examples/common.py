# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Shared configuration for examples.

Network URLs and credentials are read from environment variables, falling
back to devnet defaults.
"""

import os

# :!:>section_1
FAUCET_URL = os.getenv(
    "APTOS_FAUCET_URL",
    "https://faucet.devnet.aptoslabs.com",
)
FAUCET_AUTH_TOKEN = os.getenv("FAUCET_AUTH_TOKEN")
NODE_URL = os.getenv("APTOS_NODE_URL", "https://api.devnet.aptoslabs.com/v1")
API_KEY = os.getenv("API_KEY")
# <:!:section_1
