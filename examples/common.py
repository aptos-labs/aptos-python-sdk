# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import os
import os.path

APTOS_CORE_PATH = os.getenv(
    "APTOS_CORE_PATH",
    os.path.abspath("./aptos-core"),
)
# :!:>section_1
FAUCET_URL = os.getenv(
    "APTOS_FAUCET_URL",
    "https://faucet.devnet.aptoslabs.com",
)
INDEXER_URL = os.getenv(
    "APTOS_INDEXER_URL",
    "https://api.devnet.aptoslabs.com/v1/graphql",
)
NODE_URL = os.getenv("APTOS_NODE_URL", "https://api.devnet.aptoslabs.com/v1")
# <:!:section_1
