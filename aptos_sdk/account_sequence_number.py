# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Account sequence number management for the Aptos Python SDK.

This module provides thread-safe, asynchronous management of account sequence numbers
for transaction submission. It implements flow control mechanisms to prevent
mempool overflow and ensures proper transaction ordering.

Key features:
- Concurrent sequence number allocation with proper synchronization
- Automatic mempool flow control (max 100 transactions in flight per account)
- Timeout-based recovery from stuck transactions
- Thread-safe operations using asyncio locks
- Network state synchronization

The sequence number management follows the flow control pattern used by the
Aptos faucet to handle high-throughput transaction submission while respecting
mempool limits.

Examples:
    Basic sequence number management::

        from aptos_sdk.async_client import RestClient
        from aptos_sdk.account_address import AccountAddress
        from aptos_sdk.account_sequence_number import AccountSequenceNumber

        # Create client and sequence manager
        client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
        account_addr = AccountAddress.from_str("0x123...")
        seq_manager = AccountSequenceNumber(client, account_addr)

        # Get next sequence number for transaction
        seq_num = await seq_manager.next_sequence_number()

        # Submit transaction with seq_num...

        # Wait for all pending transactions to complete
        await seq_manager.synchronize()

    High-throughput transaction submission::

        # Submit multiple transactions concurrently
        tasks = []
        for i in range(50):
            seq_num = await seq_manager.next_sequence_number()
            task = submit_transaction_with_sequence(seq_num)
            tasks.append(task)

        # Wait for all transactions
        await asyncio.gather(*tasks)
        await seq_manager.synchronize()

    Custom configuration::

        from aptos_sdk.account_sequence_number import AccountSequenceNumberConfig

        # Custom flow control settings
        config = AccountSequenceNumberConfig()
        config.maximum_in_flight = 50  # Lower concurrency
        config.maximum_wait_time = 60  # Longer timeout
        config.sleep_time = 0.05      # Less aggressive polling

        seq_manager = AccountSequenceNumber(client, account_addr, config)
"""

from __future__ import annotations

import asyncio
import logging
import unittest
import unittest.mock
from typing import Callable, Optional

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import ApiError, RestClient


class AccountSequenceNumberConfig:
    """Configuration parameters for account sequence number management.

    This class defines the flow control parameters used by AccountSequenceNumber
    to manage transaction submission rates and handle network congestion.

    Attributes:
        maximum_in_flight: Maximum number of unconfirmed transactions allowed
            per account (default: 100). This matches Aptos mempool limits.
        maximum_wait_time: Maximum seconds to wait for transaction confirmation
            before forcing a resync (default: 30).
        sleep_time: Seconds to sleep between network polls when waiting
            (default: 0.01).

    Examples:
        Custom configuration::

            config = AccountSequenceNumberConfig()
            config.maximum_in_flight = 50   # More conservative
            config.maximum_wait_time = 60   # Longer timeout
            config.sleep_time = 0.05        # Less aggressive polling

        Low-latency configuration::

            config = AccountSequenceNumberConfig()
            config.maximum_in_flight = 10   # Fewer concurrent txns
            config.sleep_time = 0.001       # Very frequent polling

    Note:
        The default values are optimized for the Aptos mainnet and testnet
        environments. Adjust based on network conditions and requirements.
    """

    maximum_in_flight: int = 100
    maximum_wait_time: int = 30
    sleep_time: float = 0.01


class AccountSequenceNumber:
    """Thread-safe sequence number manager for high-throughput transaction submission.

    This class manages sequence number allocation for an Aptos account with built-in
    flow control to prevent mempool overflow. It implements the same strategy used
    by the Aptos faucet for reliable high-volume transaction processing.

    Flow Control Strategy:
    - Allows up to 100 transactions in flight simultaneously (configurable)
    - Monitors network state to track transaction confirmations
    - Implements automatic backoff when mempool capacity is reached
    - Provides timeout-based recovery for stuck transactions
    - Ensures FIFO ordering of sequence number allocation

    Key Features:
    - **Concurrency Safe**: Multiple async tasks can safely request sequence numbers
    - **Automatic Initialization**: Syncs with on-chain state on first use
    - **Flow Control**: Respects mempool limits to prevent rejection
    - **Recovery Mechanisms**: Handles network issues and stuck transactions
    - **Ordering Guarantees**: FIFO sequence number allocation via async locks

    Attributes:
        _client: REST client for network communication
        _account: The account address being managed
        _lock: Async lock ensuring thread safety
        _maximum_in_flight: Max unconfirmed transactions (default 100)
        _maximum_wait_time: Timeout for transaction confirmation (default 30s)
        _sleep_time: Polling interval during waits (default 0.01s)
        _last_committed_number: Last confirmed on-chain sequence number
        _current_number: Next sequence number to allocate
        _initialized: Whether the manager has been initialized

    Important Assumptions:
    - Each account should be managed by exactly one AccountSequenceNumber instance
    - The account should not be used for manual transaction submission while managed
    - Network connectivity is generally stable (handles temporary failures)
    - Transactions eventually confirm or fail (not permanently stuck)

    Usage Guidelines:
    - Call synchronize() after transaction failures to reset state
    - Use non-blocking mode (block=False) to check availability without waiting
    - Monitor logs for timeout warnings indicating potential issues
    - Configure parameters based on network conditions and requirements

    Examples:
        Basic usage::

            seq_manager = AccountSequenceNumber(client, account_address)

            # Get next sequence number
            seq_num = await seq_manager.next_sequence_number()

            # Submit transaction...

            # Wait for completion
            await seq_manager.synchronize()

        High-throughput submission::

            # Submit 50 transactions concurrently
            tasks = []
            for i in range(50):
                seq_num = await seq_manager.next_sequence_number()
                task = submit_transaction(seq_num)
                tasks.append(task)

            await asyncio.gather(*tasks)
            await seq_manager.synchronize()

        Error handling::

            try:
                seq_num = await seq_manager.next_sequence_number(block=False)
                if seq_num is None:
                    print("Too many transactions in flight, try later")
                    return

                # Submit transaction...

            except Exception as e:
                # Reset state after errors
                await seq_manager.synchronize()
                raise

    Warning:
        Do not use the same account with multiple AccountSequenceNumber instances
        simultaneously, as this will lead to sequence number conflicts and transaction
        failures.
    """

    _client: RestClient
    _account: AccountAddress
    _lock: asyncio.Lock

    _maximum_in_flight: int = 100
    _maximum_wait_time: int = 30
    _sleep_time: float = 0.01

    _last_committed_number: int = 0
    _current_number: int = 0
    _initialized = False

    def __init__(
        self,
        client: RestClient,
        account: AccountAddress,
        config: AccountSequenceNumberConfig = AccountSequenceNumberConfig(),
    ):
        """Initialize a sequence number manager for the given account.

        Args:
            client: REST client for communicating with the Aptos network.
            account: The account address to manage sequence numbers for.
            config: Configuration parameters for flow control behavior.
                Defaults to standard settings optimized for Aptos networks.

        Examples:
            Standard initialization::

                client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
                account = AccountAddress.from_str("0x123...")
                seq_manager = AccountSequenceNumber(client, account)

            Custom configuration::

                config = AccountSequenceNumberConfig()
                config.maximum_in_flight = 50
                config.maximum_wait_time = 60

                seq_manager = AccountSequenceNumber(client, account, config)

        Note:
            The sequence manager starts uninitialized and will automatically
            sync with the on-chain state on first use.
        """
        self._client = client
        self._account = account
        self._lock = asyncio.Lock()

        self._maximum_in_flight = config.maximum_in_flight
        self._maximum_wait_time = config.maximum_wait_time
        self._sleep_time = config.sleep_time

    async def next_sequence_number(self, block: bool = True) -> Optional[int]:
        """Get the next available sequence number for transaction submission.

        This method provides thread-safe allocation of sequence numbers with built-in
        flow control. It ensures FIFO ordering through an async lock and respects
        mempool limits to prevent transaction rejection.

        Args:
            block: If True (default), wait for an available sequence number when
                the maximum number of transactions are in flight. If False, return
                None immediately when no sequence numbers are available.

        Returns:
            The next sequence number to use for transaction submission, or None
            if block=False and the maximum number of transactions are in flight.

        Raises:
            Exception: Network communication errors or other failures during
                synchronization with the blockchain state.

        Examples:
            Blocking mode (default)::

                # This will wait if necessary
                seq_num = await seq_manager.next_sequence_number()
                transaction.sequence_number = seq_num

            Non-blocking mode::

                # Check availability without waiting
                seq_num = await seq_manager.next_sequence_number(block=False)
                if seq_num is None:
                    print("Account busy, try again later")
                    return

            Batch processing::

                batch_size = 10
                sequence_numbers = []

                for i in range(batch_size):
                    seq_num = await seq_manager.next_sequence_number()
                    sequence_numbers.append(seq_num)

                # Submit all transactions...

        Note:
            This method automatically initializes the sequence manager on first use
            by querying the current on-chain sequence number. Subsequent calls use
            the cached state with periodic network updates for flow control.
        """
        async with self._lock:
            if not self._initialized:
                await self._initialize()
            # If there are more than self._maximum_in_flight in flight, wait for a slot.
            # Or at least check to see if there is a slot and exit if in non-blocking mode.
            if (
                self._current_number - self._last_uncommitted_number
                >= self._maximum_in_flight
            ):
                await self._update()
                if (
                    self._current_number - self._last_uncommitted_number
                    >= self._maximum_in_flight
                ):
                    if not block:
                        return None
                    await self._resync(
                        lambda acn: acn._current_number - acn._last_uncommitted_number
                        >= acn._maximum_in_flight
                    )

            next_number = self._current_number
            self._current_number += 1
        return next_number

    async def _initialize(self):
        """Initialize the sequence manager with current on-chain state.

        This method is automatically called on first use of next_sequence_number.
        It queries the network to get the current sequence number for the account
        and sets up the internal state tracking.

        Note:
            This is an internal method. Users should not call it directly as it's
            automatically invoked when needed.
        """
        self._initialized = True
        self._current_number = await self._current_sequence_number()
        self._last_uncommitted_number = self._current_number

    async def synchronize(self):
        """Wait for all pending transactions to complete or timeout.

        This method creates a synchronization barrier that blocks all other
        operations until either:
        1. All pending transactions are confirmed on-chain, or
        2. The maximum wait time is exceeded

        During synchronization, no new sequence numbers can be allocated,
        ensuring a consistent view of the account state.

        Use Cases:
        - After transaction submission to ensure completion
        - Before critical operations requiring known account state
        - After errors to reset and resync with network state
        - At application shutdown to wait for pending operations

        Examples:
            Wait for transaction batch completion::

                # Submit transactions
                for data in transaction_batch:
                    seq_num = await seq_manager.next_sequence_number()
                    await submit_transaction(data, seq_num)

                # Wait for all to complete
                await seq_manager.synchronize()
                print("All transactions processed")

            Error recovery::

                try:
                    # Transaction operations...
                    pass
                except Exception as e:
                    logging.error(f"Transaction failed: {e}")
                    # Reset state
                    await seq_manager.synchronize()

        Raises:
            Exception: Network communication errors or other failures during
                the synchronization process.

        Warning:
            This method may take significant time to complete if transactions
            are slow to confirm. Monitor the logs for timeout warnings.
        """
        async with self._lock:
            await self._update()
            await self._resync(
                lambda acn: acn._last_uncommitted_number != acn._current_number
            )

    async def _resync(self, check: Callable[[AccountSequenceNumber], bool]):
        """Force resynchronization with the blockchain state.

        This internal method implements the timeout and recovery logic when
        transactions are not confirming as expected. It polls the network
        state and attempts to determine which transactions have confirmed.

        Args:
            check: A callable that returns True while resync should continue.
                  Used to implement different resync conditions.

        Note:
            This is an internal method called within the async lock context.
            It should not be called directly by users.
        """
        start_time = await self._client.current_timestamp()
        failed = False
        while check(self):
            ledger_time = await self._client.current_timestamp()
            if ledger_time - start_time > self._maximum_wait_time:
                logging.warn(
                    f"Waited over {self._maximum_wait_time} seconds for a transaction to commit, resyncing {self._account}"
                )
                failed = True
                break
            else:
                await asyncio.sleep(self._sleep_time)
                await self._update()
        if not failed:
            return
        for seq_num in range(self._last_uncommitted_number + 1, self._current_number):
            while True:
                try:
                    result = (
                        await self._client.account_transaction_sequence_number_status(
                            self._account, seq_num
                        )
                    )
                    if result:
                        break
                except ApiError as error:
                    if error.status_code == 404:
                        break
                    raise
        await self._initialize()

    async def _update(self):
        """Update the last committed sequence number from the network.

        Returns:
            The current sequence number from the blockchain.

        Note:
            This is an internal method for network state synchronization.
        """
        self._last_uncommitted_number = await self._current_sequence_number()
        return self._last_uncommitted_number

    async def _current_sequence_number(self) -> int:
        """Get the current sequence number for the account from the network.

        Returns:
            The current sequence number as reported by the blockchain.

        Note:
            This is an internal method that queries the network directly.
        """
        return await self._client.account_sequence_number(self._account)


class Test(unittest.IsolatedAsyncioTestCase):
    """Test suite for AccountSequenceNumber functionality.

    Tests the sequence number management including:
    - Sequential number allocation
    - Flow control when at capacity
    - Network state synchronization
    - Blocking vs non-blocking behavior
    """

    async def test_common_path(self):
        """Test the common usage patterns of AccountSequenceNumber.

        This test verifies:
        - Sequential number allocation starting from the current on-chain state
        - Proper handling of on-chain state updates (e.g., 0 -> 5 -> 100+)
        - Non-blocking behavior returns None when at capacity
        - Synchronization completes when network state matches expectations
        """
        patcher = unittest.mock.patch(
            "aptos_sdk.async_client.RestClient.account_sequence_number", return_value=0
        )
        patcher.start()

        rest_client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
        account_sequence_number = AccountSequenceNumber(
            rest_client, AccountAddress.from_str("0xf")
        )
        last_seq_num = 0
        for seq_num in range(5):
            last_seq_num = await account_sequence_number.next_sequence_number()
            self.assertEqual(last_seq_num, seq_num)

        patcher.stop()
        patcher = unittest.mock.patch(
            "aptos_sdk.async_client.RestClient.account_sequence_number", return_value=5
        )
        patcher.start()

        for seq_num in range(AccountSequenceNumber._maximum_in_flight):
            last_seq_num = await account_sequence_number.next_sequence_number()
            self.assertEqual(last_seq_num, seq_num + 5)

        self.assertEqual(
            await account_sequence_number.next_sequence_number(block=False), None
        )
        next_sequence_number = last_seq_num + 1
        patcher.stop()
        patcher = unittest.mock.patch(
            "aptos_sdk.async_client.RestClient.account_sequence_number",
            return_value=next_sequence_number,
        )
        patcher.start()

        self.assertNotEqual(account_sequence_number._current_number, last_seq_num)
        await account_sequence_number.synchronize()
        self.assertEqual(account_sequence_number._current_number, next_sequence_number)
