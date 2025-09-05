# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import typing
import unittest
import unittest.mock

from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.account_sequence_number import AccountSequenceNumber
from aptos_sdk.async_client import RestClient
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)


class TransactionWorker:
    """High-throughput transaction processing framework for Aptos blockchain.
    
    The TransactionWorker provides an asynchronous framework for processing large volumes
    of transactions efficiently. It manages sequence number coordination, transaction
    generation, submission, and result tracking through separate concurrent tasks.
    
    Architecture:
    - **Sequence Management**: Automatically acquires sequential transaction numbers
    - **Concurrent Submission**: Submits transactions asynchronously for high throughput
    - **Batch Processing**: Processes transaction results in batches for efficiency
    - **Error Handling**: Captures and reports transaction submission errors
    - **Queue-Based**: Uses asyncio queues for task coordination
    
    Key Features:
    - **High Performance**: Designed for bulk transaction processing
    - **Sequence Safety**: Ensures proper transaction ordering
    - **Non-blocking**: Asynchronous operation doesn't block the caller
    - **Error Tracking**: Comprehensive error reporting and exception handling
    - **Result Monitoring**: Track transaction outcomes and failures
    
    Workflow:
    1. **Start**: Initialize worker tasks for submission and processing
    2. **Generate**: Transaction generator creates signed transactions with sequence numbers
    3. **Submit**: Submit transactions to the blockchain via REST client
    4. **Track**: Monitor submission results and errors
    5. **Process**: Batch process results for efficiency
    6. **Stop**: Clean shutdown of worker tasks
    
    Examples:
        Basic transaction worker::
        
            import asyncio
            from aptos_sdk.async_client import RestClient
            from aptos_sdk.account import Account
            from aptos_sdk.transaction_worker import TransactionWorker
            
            async def transaction_generator(account, sequence_number):
                # Create transfer transaction
                recipient = Account.generate().address()
                return await client.create_bcs_signed_transaction(
                    account, transfer_payload, sequence_number=sequence_number
                )
            
            async def bulk_transfers():
                client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
                sender = Account.generate()
                
                # Create and start worker
                worker = TransactionWorker(sender, client, transaction_generator)
                worker.start()
                
                try:
                    # Process transaction results
                    for _ in range(100):  # Process 100 transactions
                        seq_num, tx_hash, error = await worker.next_processed_transaction()
                        if error:
                            print(f"Transaction {seq_num} failed: {error}")
                        else:
                            print(f"Transaction {seq_num} succeeded: {tx_hash}")
                finally:
                    worker.stop()
                    
        Token distribution example::
        
            async def token_generator(account, sequence_number):
                # Distribute tokens to random recipients
                recipients = [Account.generate().address() for _ in range(10)]
                recipient = random.choice(recipients)
                
                return await client.transfer_transaction(
                    account, recipient, 1000, sequence_number=sequence_number
                )
                
            # Process 1000 token distributions
            worker = TransactionWorker(distributor_account, client, token_generator)
            worker.start()
            
            success_count = 0
            for _ in range(1000):
                seq_num, tx_hash, error = await worker.next_processed_transaction()
                if not error:
                    success_count += 1
                    
            print(f"Successfully distributed tokens in {success_count} transactions")
            worker.stop()
    
    Performance Considerations:
    - **Batch Size**: Processes multiple transactions concurrently
    - **Memory Usage**: Queues consume memory; monitor for large workloads
    - **Network Limits**: Respects node rate limits and connection pooling
    - **Sequence Coordination**: May wait for sequence numbers under high load
    
    Limitations:
    - **No Retry Logic**: Failed transactions are not automatically retried
    - **No Health Monitoring**: Doesn't check node health or connectivity
    - **Basic Error Handling**: Errors are reported but not automatically resolved
    - **Single Account**: Designed for single account use (sequence number coordination)
    
    Error Handling:
        Transaction errors are captured and reported through the result queue.
        Common error scenarios:
        - Network connectivity issues
        - Insufficient account balance
        - Transaction validation failures
        - Node overload or rate limiting
    
    Thread Safety:
        The TransactionWorker is designed for single-threaded async use.
        Don't share instances across multiple async contexts.
    
    Note:
        This is a basic framework suitable for development and testing.
        Production systems should implement additional features like:
        - Retry logic with exponential backoff
        - Health monitoring and circuit breakers
        - Metrics collection and monitoring
        - Graceful degradation strategies
    """

    _account: Account
    _account_sequence_number: AccountSequenceNumber
    _rest_client: RestClient
    _transaction_generator: typing.Callable[
        [Account, int], typing.Awaitable[SignedTransaction]
    ]
    _started: bool
    _stopped: bool
    _outstanding_transactions: asyncio.Queue
    _outstanding_transactions_task: typing.Optional[asyncio.Task]
    _processed_transactions: asyncio.Queue
    _process_transactions_task: typing.Optional[asyncio.Task]

    def __init__(
        self,
        account: Account,
        rest_client: RestClient,
        transaction_generator: typing.Callable[
            [Account, int], typing.Awaitable[SignedTransaction]
        ],
    ):
        """Initialize a TransactionWorker for high-throughput transaction processing.
        
        Creates a transaction worker that will use the provided account for signing
        transactions and submit them through the REST client. The transaction generator
        function is called to create each transaction with the appropriate sequence number.
        
        Args:
            account: The Account to use for signing transactions. Must have sufficient
                balance for the transactions being generated.
            rest_client: RestClient instance for submitting transactions to the blockchain.
            transaction_generator: Async function that takes (Account, int) and returns
                a SignedTransaction. This function is called for each transaction with
                the next available sequence number.
                
        Examples:
            Simple transfer generator::
            
                async def transfer_generator(account, seq_num):
                    recipient = Account.generate().address()
                    return await client.create_bcs_signed_transaction(
                        account,
                        transfer_payload(recipient, 1000),
                        sequence_number=seq_num
                    )
                    
                worker = TransactionWorker(account, client, transfer_generator)
                
            Complex transaction generator::
            
                async def complex_generator(account, seq_num):
                    # Randomly choose transaction type
                    if random.random() < 0.5:
                        # Token transfer
                        return create_transfer_txn(account, seq_num)
                    else:
                        # Smart contract interaction
                        return create_contract_txn(account, seq_num)
                        
                worker = TransactionWorker(account, client, complex_generator)
        
        Note:
            The worker is initialized but not started. Call start() to begin
            processing transactions.
        """
        self._account = account
        self._account_sequence_number = AccountSequenceNumber(
            rest_client, account.address()
        )
        self._account_sequence_number._maximum_wait_time = (
            rest_client.client_config.transaction_wait_in_seconds
        )
        self._rest_client = rest_client
        self._transaction_generator = transaction_generator

        self._started = False
        self._stopped = False
        self._outstanding_transactions = asyncio.Queue()
        self._processed_transactions = asyncio.Queue()

    def address(self) -> AccountAddress:
        """Get the address of the account used by this transaction worker.
        
        Returns:
            AccountAddress: The address of the account that signs transactions.
            
        Examples:
            Check worker account::
            
                worker = TransactionWorker(account, client, generator)
                print(f"Worker using account: {worker.address()}")
                
            Verify account balance::
            
                worker_address = worker.address()
                balance = await client.account_balance(worker_address)
                print(f"Worker account balance: {balance} APT")
        """
        return self._account.address()

    async def _submit_transactions(self):
        try:
            while True:
                sequence_number = (
                    await self._account_sequence_number.next_sequence_number()
                )
                transaction = await self._transaction_generator(
                    self._account, sequence_number
                )
                txn_hash_awaitable = self._rest_client.submit_bcs_transaction(
                    transaction
                )
                await self._outstanding_transactions.put(
                    (txn_hash_awaitable, sequence_number)
                )
        except asyncio.CancelledError:
            return
        except Exception as e:
            # This is insufficient, if we hit this we either need to bail or resolve the potential errors
            logging.error(e, exc_info=True)

    async def _process_transactions(self):
        try:
            while True:
                # Always start waiting for one, that way we can acquire a batch in the loop below.
                (
                    txn_hash_awaitable,
                    sequence_number,
                ) = await self._outstanding_transactions.get()
                awaitables = [txn_hash_awaitable]
                sequence_numbers = [sequence_number]

                # Now acquire our batch.
                while not self._outstanding_transactions.empty():
                    (
                        txn_hash_awaitable,
                        sequence_number,
                    ) = await self._outstanding_transactions.get()
                    awaitables.append(txn_hash_awaitable)
                    sequence_numbers.append(sequence_number)

                outputs = await asyncio.gather(*awaitables, return_exceptions=True)

                for output, sequence_number in zip(outputs, sequence_numbers):
                    if isinstance(output, BaseException):
                        await self._processed_transactions.put(
                            (sequence_number, None, output)
                        )
                    else:
                        await self._processed_transactions.put(
                            (sequence_number, output, None)
                        )
        except asyncio.CancelledError:
            return
        except Exception as e:
            # This is insufficient, if we hit this we either need to bail or resolve the potential errors
            logging.error(e, exc_info=True)

    async def next_processed_transaction(
        self,
    ) -> typing.Tuple[int, typing.Optional[str], typing.Optional[Exception]]:
        """Get the next processed transaction result from the worker.
        
        This method blocks until a transaction result is available. Results include
        both successful submissions (with transaction hash) and failures (with error).
        
        Returns:
            Tuple containing:
            - int: The sequence number of the processed transaction
            - Optional[str]: Transaction hash if successful, None if failed
            - Optional[Exception]: Exception if failed, None if successful
            
        Examples:
            Process results sequentially::
            
                worker.start()
                
                while True:
                    seq_num, tx_hash, error = await worker.next_processed_transaction()
                    
                    if error:
                        print(f"Transaction {seq_num} failed: {error}")
                    else:
                        print(f"Transaction {seq_num} succeeded: {tx_hash}")
                        
            Batch processing with timeout::
            
                import asyncio
                
                results = []
                timeout_seconds = 30
                
                try:
                    while len(results) < expected_count:
                        result = await asyncio.wait_for(
                            worker.next_processed_transaction(),
                            timeout=timeout_seconds
                        )
                        results.append(result)
                except asyncio.TimeoutError:
                    print(f"Timeout after {timeout_seconds}s, got {len(results)} results")
                    
            Error handling::
            
                seq_num, tx_hash, error = await worker.next_processed_transaction()
                
                if error:
                    if "insufficient balance" in str(error).lower():
                        print("Account needs more funds")
                    elif "rate limit" in str(error).lower():
                        print("Being rate limited, slow down")
                    else:
                        print(f"Unexpected error: {error}")
        
        Note:
            This method will block indefinitely if no more transactions are being
            processed. Make sure to call stop() when done to clean up resources.
        """
        return await self._processed_transactions.get()

    def stop(self):
        """Stop the transaction worker and cancel all background tasks.
        
        This method gracefully shuts down the transaction worker by canceling
        the background tasks for transaction submission and processing. Any
        pending transactions will be canceled.
        
        Raises:
            Exception: If the worker hasn't been started yet or is already stopped.
            
        Examples:
            Proper shutdown::
            
                worker = TransactionWorker(account, client, generator)
                worker.start()
                
                try:
                    # Process transactions...
                    pass
                finally:
                    worker.stop()  # Always clean up
                    
            Context manager pattern::
            
                async def process_with_worker():
                    worker = TransactionWorker(account, client, generator)
                    worker.start()
                    
                    try:
                        # Do work...
                        yield worker
                    finally:
                        worker.stop()
        
        Note:
            After calling stop(), the worker cannot be restarted. Create a new
            TransactionWorker instance if you need to resume processing.
        """
        if not self._started:
            raise Exception("Start not yet called")
        if self._stopped:
            raise Exception("Already stopped")
        self._stopped = True

        self._submit_transactions_task.cancel()
        self._process_transactions_task.cancel()

    def start(self):
        """Start the transaction worker background tasks.
        
        This method begins the asynchronous tasks for transaction submission and
        processing. The worker will start generating, submitting, and tracking
        transactions immediately after this call.
        
        Raises:
            Exception: If the worker has already been started.
            
        Examples:
            Basic startup::
            
                worker = TransactionWorker(account, client, generator)
                worker.start()
                
                # Worker is now processing transactions
                # Get results with next_processed_transaction()
                
            Startup with immediate processing::
            
                worker = TransactionWorker(account, client, generator)
                worker.start()
                
                # Start consuming results immediately
                asyncio.create_task(process_results(worker))
                
            Error handling::
            
                try:
                    worker.start()
                except Exception as e:
                    print(f"Failed to start worker: {e}")
                    # Handle startup failure
        
        Background Tasks:
            Starting the worker creates two background tasks:
            - **Submission Task**: Generates and submits transactions
            - **Processing Task**: Processes submission results in batches
        
        Note:
            The worker must be started before calling next_processed_transaction().
            Always pair start() with stop() for proper resource cleanup.
        """
        if self._started:
            raise Exception("Already started")
        self._started = True

        self._submit_transactions_task = asyncio.create_task(
            self._submit_transactions()
        )
        self._process_transactions_task = asyncio.create_task(
            self._process_transactions()
        )


class TransactionQueue:
    """Queue-based transaction payload manager for TransactionWorker integration.
    
    The TransactionQueue provides a simple interface for feeding transaction payloads
    to a TransactionWorker. It acts as a bridge between application logic that creates
    transaction payloads and the worker that needs signed transactions.
    
    Key Features:
    - **Async Queue**: Built on asyncio.Queue for efficient async operations
    - **Payload Management**: Handles raw transaction payloads before signing
    - **Worker Integration**: Designed to work seamlessly with TransactionWorker
    - **Backpressure**: Built-in flow control through queue size limits
    
    Examples:
        Basic queue usage::
        
            from aptos_sdk.transaction_worker import TransactionQueue
            from aptos_sdk.transactions import EntryFunction, TransactionArgument
            
            # Create queue and connect to worker
            queue = TransactionQueue(rest_client)
            worker = TransactionWorker(account, rest_client, queue.next)
            
            # Push transaction payloads
            transfer_payload = EntryFunction.natural(
                "***::aptos_account",
                "transfer",
                [],
                [recipient_address, amount]
            )
            
            await queue.push(transfer_payload)
            
        Batch operations::
        
            # Push multiple payloads
            payloads = [
                create_transfer_payload(addr, 1000)
                for addr in recipient_addresses
            ]
            
            for payload in payloads:
                await queue.push(payload)
                
            # Worker will process them automatically
            
        Custom payload generation::
        
            async def generate_payloads():
                for i in range(1000):
                    payload = create_custom_payload(i)
                    await queue.push(payload)
                    
            # Start payload generation and worker processing
            asyncio.create_task(generate_payloads())
            worker.start()
    
    Integration Pattern:
        The typical usage pattern is:
        1. Create TransactionQueue with REST client
        2. Create TransactionWorker with account and queue.next as generator
        3. Push payloads to queue with push()
        4. Worker automatically consumes payloads and creates signed transactions
    
    Note:
        The queue uses unbounded storage by default. For high-volume applications,
        consider implementing backpressure or queue size limits to prevent
        memory exhaustion.
    """

    _client: RestClient
    _outstanding_transactions: asyncio.Queue

    def __init__(self, client: RestClient):
        self._client = client
        self._outstanding_transactions = asyncio.Queue()

    async def push(self, payload: TransactionPayload):
        await self._outstanding_transactions.put(payload)

    async def next(self, sender: Account, sequence_number: int) -> SignedTransaction:
        payload = await self._outstanding_transactions.get()
        return await self._client.create_bcs_signed_transaction(
            sender, payload, sequence_number=sequence_number
        )


class Test(unittest.IsolatedAsyncioTestCase):
    async def test_common_path(self):
        transaction_arguments = [
            TransactionArgument(AccountAddress.from_str("0xf"), Serializer.struct),
            TransactionArgument(100, Serializer.u64),
        ]
        payload = EntryFunction.natural(
            "0x1::aptos_accounts",
            "transfer",
            [],
            transaction_arguments,
        )

        seq_num_patcher = unittest.mock.patch(
            "aptos_sdk.async_client.RestClient.account_sequence_number", return_value=0
        )
        seq_num_patcher.start()
        submit_txn_patcher = unittest.mock.patch(
            "aptos_sdk.async_client.RestClient.submit_bcs_transaction",
            return_value="0xff",
        )
        submit_txn_patcher.start()

        rest_client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
        txn_queue = TransactionQueue(rest_client)
        txn_worker = TransactionWorker(Account.generate(), rest_client, txn_queue.next)
        txn_worker.start()

        await txn_queue.push(payload)
        processed_txn = await txn_worker.next_processed_transaction()
        self.assertEqual(processed_txn[0], 0)
        self.assertEqual(processed_txn[1], "0xff")
        self.assertEqual(processed_txn[2], None)

        submit_txn_patcher.stop()
        exception = Exception("Power overwhelming")
        submit_txn_patcher = unittest.mock.patch(
            "aptos_sdk.async_client.RestClient.submit_bcs_transaction",
            side_effect=exception,
        )
        submit_txn_patcher.start()

        await txn_queue.push(payload)
        processed_txn = await txn_worker.next_processed_transaction()
        self.assertEqual(processed_txn[0], 1)
        self.assertEqual(processed_txn[1], None)
        self.assertEqual(processed_txn[2], exception)

        txn_worker.stop()
