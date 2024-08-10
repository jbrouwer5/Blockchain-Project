import hashlib
import time
import threading
from decimal import Decimal
from typing import List, Optional


class BlockchainHelper:
    @staticmethod
    def double_sha256(data: str) -> str:
        encoded_data = data.encode()
        first = hashlib.sha256(encoded_data).digest()
        second = hashlib.sha256(first).hexdigest()
        return second


class Output:
    def __init__(self, value: int, script: str):
        self.value = value  # Value in milli-CapnJacks
        self.script = script

    def __repr__(self):
        return f"Value: {Decimal(self.value) / 1000} CapnJacks, Script: {self.script}"


class Transaction(BlockchainHelper):
    def __init__(
        self,
        version_number: int = 1,
        list_of_inputs: List[str] = [""],
        list_of_outputs: List[Output] = [Output(0, "")],
    ):
        self.version_number = version_number
        self.in_counter = len(list_of_inputs)
        self.list_of_inputs = list_of_inputs
        self.out_counter = len(list_of_outputs)
        self.list_of_outputs = list_of_outputs
        self.transaction_hash = self.calculate_transaction_hash()

    def calculate_transaction_hash(self) -> str:
        transaction_data = f"{self.version_number}{self.in_counter}{self.list_of_inputs}{self.out_counter}{self.list_of_outputs}"
        return self.double_sha256(transaction_data)

    def print_transaction(self):
        print(
            f"Transaction hash: {self.transaction_hash}\nInputs: {self.list_of_inputs}\nOutputs: {self.list_of_outputs}\n"
        )


class BlockHeader(BlockchainHelper):
    def __init__(self, previous_hash: str, merkle_root: str):
        self.version_number = 1
        self.hashPrevBlock = previous_hash
        self.hashMerkleRoot = merkle_root
        self.timestamp = int(time.time())
        self.bits = 0x1E200000
        self.nonce = 0
        self.hash = self.calculate_block_hash()

    def calculate_block_hash(self) -> str:
        header_data = f"{self.version_number}{self.hashPrevBlock}{self.hashMerkleRoot}{self.timestamp}{self.bits}{self.nonce}"
        return self.double_sha256(header_data)

    def __repr__(self):
        return (
            f"Block Header:\n Hash: {self.hash}\n Previous Hash: {self.hashPrevBlock}\n"
        )


class Block(BlockchainHelper):
    def __init__(self, previous_hash: str, transactions: List[Transaction]):
        self.transactions = transactions
        self.merkle_tree = self.calculate_merkle_tree()
        self.merkle_root = self.merkle_tree[0]
        self.header = BlockHeader(previous_hash, self.merkle_root)

    def get_merkle_root(self) -> str:
        return self.calculate_merkle_tree()[0]

    def calculate_merkle_tree(self) -> List[str]:
        if not self.transactions:
            return [self.double_sha256("")]

        transaction_hashes = [tx.transaction_hash for tx in self.transactions]
        while len(transaction_hashes) > 1:
            is_odd_number_of_transactions = len(transaction_hashes) % 2 != 0
            if is_odd_number_of_transactions:
                transaction_hashes.append(transaction_hashes[-1])
            transaction_hashes = [
                self.double_sha256(transaction_hashes[i] + transaction_hashes[i + 1])
                for i in range(0, len(transaction_hashes), 2)
            ]
        return transaction_hashes

    def print_block(self):
        print(f"Block Hash: {self.header.hash}")
        print("Transactions:")
        for tx in self.transactions:
            tx.print_transaction()


class TxnMemoryPool:
    def __init__(self):
        self.transactions = []

    def add_transaction(self, transaction: Transaction):
        self.transactions.append(transaction)

    def get_transactions(self) -> List[Transaction]:
        return self.transactions

    def clear_transactions(self):
        self.transactions = []


class Miner:
    MAX_TXNS = 10

    def __init__(self, blockchain: "Blockchain", mempool: TxnMemoryPool):
        self.blockchain = blockchain
        self.mempool = mempool

    def create_coinbase_transaction(self) -> Transaction:
        return Transaction(
            list_of_inputs=["Coinbase"],
            list_of_outputs=[Output(5000, "Coinbase to Miner")],  # 5 CapnJacks
        )

    def calculate_target(self, bits: int) -> int:
        exponent = bits >> 24
        coefficient = bits & 0xFFFFFF
        target = coefficient * 2 ** (8 * (exponent - 3))
        return target

    def mine_block(self):
        transactions = self.mempool.get_transactions()
        transactions = transactions[
            : self.MAX_TXNS - 1
        ]  # Reserve space for coinbase transaction
        transactions.insert(0, self.create_coinbase_transaction())

        previous_hash = self.blockchain.chain[-1].header.hash
        new_block = Block(previous_hash, transactions)

        target = self.calculate_target(new_block.header.bits)
        target_hex = f"{target:064x}"

        start_time = time.time()

        while int(new_block.header.hash, 16) >= int(target_hex, 16):
            new_block.header.nonce += 1
            new_block.header.hash = new_block.header.calculate_block_hash()

            # Print progress every 100000 iterations to monitor the process
            if new_block.header.nonce % 100000 == 0:
                print(
                    f"Nonce: {new_block.header.nonce}, Current Hash: {new_block.header.hash}"
                )

        end_time = time.time()
        mining_time = end_time - start_time
        print(f"Block mined! Hash: {new_block.header.hash}")
        print(f"Time taken to mine block: {mining_time:.2f} seconds")

        self.blockchain.add_block(transactions)
        self.mempool.clear_transactions()


class Blockchain:
    def __init__(self):
        genesis_block = Block(
            previous_hash="0" * 64,
            transactions=[
                Transaction(
                    list_of_inputs=["Genesis Input"],
                    list_of_outputs=[Output(0, "Genesis Output")],
                )
            ],
        )
        # Explicitly set the genesis block's header and hash so it is consistent
        # across all nodes in the network.
        genesis_block.header.hash = (
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        self.chain = [genesis_block]
        self.blocks_hash_dict = {genesis_block.header.hash: genesis_block}
        self.transaction_hash_dict = {}
        print("Genesis block created:", flush=True)
        genesis_block.print_block()

    def add_block(self, transactions: List[Transaction]) -> Block:
        previous_hash = self.chain[-1].header.hash
        new_block = Block(previous_hash, transactions)
        self.chain.append(new_block)
        self.blocks_hash_dict[new_block.header.hash] = new_block
        for tx in transactions:
            self.transaction_hash_dict[tx.transaction_hash] = tx
        return new_block

    def get_block_by_height(self, height: int) -> Optional[Block]:
        if 0 <= height < len(self.chain):
            return self.chain[height]
        else:
            print("Invalid height")
            return None

    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        return self.blocks_hash_dict.get(block_hash)

    def get_transaction_by_hash(self, transaction_hash: str) -> Optional[Transaction]:
        return self.transaction_hash_dict.get(transaction_hash)

    def print_blockchain(self):
        print(f"Blockchain\nHeight: {len(self.chain)}")
        for block in self.chain:
            block.print_block()


def create_random_transaction() -> Transaction:
    timestamp = int(time.time())
    random_number = hashlib.sha256(f"{timestamp}".encode()).hexdigest()
    return Transaction(
        list_of_inputs=[f"input_{random_number}"],
        list_of_outputs=[Output(1000, f"output_{random_number}")],
    )


def test_blockchain_mining():
    # Create a new Blockchain and TxnMemoryPool
    blockchain = Blockchain()
    mempool = TxnMemoryPool()
    miner = Miner(blockchain, mempool)

    # Pre-create 91 new transactions and add them to the TxnMemoryPool
    for _ in range(91):
        mempool.add_transaction(create_random_transaction())

    # Mine blocks until all transactions are processed
    while mempool.get_transactions():
        miner.mine_block()

    # Print the entire blockchain for verification
    blockchain.print_blockchain()

    # Print out the block height of the tip of the chain
    block_height = len(blockchain.chain) - 1
    print(f"Block height of the tip of the chain: {block_height}")


# test_blockchain_mining()
