import grpc
from concurrent import futures
import time
import random
import socket
import threading

import full_node_pb2
import full_node_pb2_grpc
import dns_seed_pb2
import dns_seed_pb2_grpc

from blockchain_classes import (
    Blockchain,
    TxnMemoryPool,
    Miner,
    Transaction,
    Output,
    Block,
)


class FullNodeService(full_node_pb2_grpc.FullNodeServicer):
    def __init__(self):
        self.known_peers = []
        self.mempool = TxnMemoryPool()  # Transaction memory pool
        self.blockchain = Blockchain()  # Blockchain instance
        self.miner = Miner(self.blockchain, self.mempool)  # Miner instance
        self.mining_active = True
        self.local_address = ""  # This will be set after the server starts

    def start_mining(self):
        while self.mining_active:
            # Mine a block using the miner instance
            self.miner.mine_block()
            print(
                f"Mined a new block: {self.blockchain.chain[-1].header.hash}",
                flush=True,
            )

            # Broadcast the new block to all known peers
            self.gossip_block(self.blockchain.chain[-1])

            # Random sleep to reduce chance of simultaneous mining
            time.sleep(random.randint(0, 3))

    def generate_and_broadcast_transaction(self):
        transaction = Transaction(
            list_of_inputs=["Generated Input"],
            list_of_outputs=[Output(random.randint(1000, 5000), "Generated Output")],
        )
        self.mempool.add_transaction(transaction)
        print(f"Generated new transaction: {transaction.transaction_hash}", flush=True)
        self.gossip_transaction(transaction)

    def start(self):
        threading.Thread(target=self.start_mining, daemon=True).start()

    def Handshake(self, request, context):
        # This function is called by the peer when it wants to establish a connection with the Full Node
        requester_address = (
            request.addrMe
        )  # The address of the node initiating the handshake
        print(f"Handshake received from {requester_address}", flush=True)

        # Add the new peer to the list of known peers if it's not the local node's address
        if (
            requester_address != self.local_address
            and requester_address not in self.known_peers
        ):
            self.known_peers.append(requester_address)
            print(
                f"Added the requesting node: {requester_address} to known peers.",
                flush=True,
            )

        # Return the list of known peers to the requester
        print(
            f"Returning known peers to requester node: {requester_address}. Sending: {self.known_peers}.",
            flush=True,
        )
        return full_node_pb2.HandshakeResponse(knownPeers=self.known_peers)

    def NewTransactionBroadcast(self, request, context):
        transaction_hash = request.transaction_data
        print(f"Received new transaction: {transaction_hash}", flush=True)

        # Reconstruct the transaction from the hash (you may need to pass additional data)
        transaction = Transaction(
            list_of_inputs=["Reconstructed Input"],
            list_of_outputs=[Output(1000, "Reconstructed Output")],
        )
        if transaction.transaction_hash not in [
            tx.transaction_hash for tx in self.mempool.get_transactions()
        ]:
            self.mempool.add_transaction(transaction)
            self.gossip_transaction(transaction)

        # Random sleep to reduce chance of simultaneous mining
        time.sleep(random.randint(0, 3))

        return full_node_pb2.Empty()

    def NewBlockBroadcast(self, request, context):
        block_hash = request.block_data
        peer_address = context.peer()
        peer_ip = peer_address.split(":")[1]
        print(f"Received new block from {peer_ip}: {block_hash}", flush=True)

        # Reconstruct the block from the hash (you may need to pass additional data)
        block = self.blockchain.get_block_by_hash(block_hash)
        if not block:
            # Assuming block data needs to be recreated or received fully (details needed)
            block = Block(
                previous_hash=self.blockchain.chain[-1].header.hash, transactions=[]
            )
            self.blockchain.add_block(block.transactions)
            self.gossip_block(block)

        return full_node_pb2.Empty()

    def gossip_transaction(self, transaction):
        print(
            f"Gossiping transaction {transaction.transaction_hash} to peers: {self.known_peers}",
            flush=True,
        )
        for peer in self.known_peers:
            ip, port = peer.split(":")
            with grpc.insecure_channel(f"{ip}:{port}") as channel:
                stub = full_node_pb2_grpc.FullNodeStub(channel)
                try:
                    stub.NewTransactionBroadcast(
                        full_node_pb2.NewTransactionRequest(
                            transaction_data=transaction.transaction_hash
                        )
                    )
                except grpc.RpcError as e:
                    print(f"Failed to broadcast transaction to {peer}: {e}", flush=True)

    def gossip_block(self, block):
        print(
            f"Gossiping block {block.header.hash} to peers: {self.known_peers}",
            flush=True,
        )
        for peer in self.known_peers:
            ip, port = peer.split(":")
            with grpc.insecure_channel(f"{ip}:{port}") as channel:
                stub = full_node_pb2_grpc.FullNodeStub(channel)
                try:
                    stub.NewBlockBroadcast(
                        full_node_pb2.NewBlockRequest(block_data=block.header.hash)
                    )
                except grpc.RpcError as e:
                    print(f"Failed to broadcast block to {peer}: {e}", flush=True)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    full_node_service = FullNodeService()
    full_node_pb2_grpc.add_FullNodeServicer_to_server(full_node_service, server)

    # Bind to port 0 to let the OS choose an available port
    port = server.add_insecure_port("[::]:0")
    server.start()

    # Set the dynamically assigned port in the FullNodeService instance
    full_node_service.local_address = (
        f"{socket.gethostbyname(socket.gethostname())}:{port}"
    )

    return server, full_node_service, port


def register_with_dns_seed(port):
    # Use socket to get the current IP address of the host
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    with grpc.insecure_channel("dns_seed:12345") as channel:
        stub = dns_seed_pb2_grpc.RegistrarStub(channel)
        response = stub.RegisterNode(
            dns_seed_pb2.RegistrationRequest(
                version="1.0",
                time=str(time.time()),
                addrMe=f"{local_ip}:{port}",  # Register with the IP and dynamically assigned port
            )
        )
        return response.last_registered_node


def perform_handshake_with_peer(full_node_service, peer_address):
    ip, port = peer_address.split(":")
    with grpc.insecure_channel(f"{ip}:{port}") as channel:
        stub = full_node_pb2_grpc.FullNodeStub(channel)
        try:
            print(f"Calling handshake function on {peer_address}", flush=True)
            response = stub.Handshake(
                full_node_pb2.HandshakeRequest(
                    version="1.0",
                    time=str(time.time()),
                    addrMe=full_node_service.local_address,
                    bestHeight=len(
                        full_node_service.blockchain.chain
                    ),  # Example blockchain height
                )
            )

            print(
                f"Handshake with {peer_address} succeeded. Known peers received: {response.knownPeers}.",
                flush=True,
            )
            if (
                peer_address not in full_node_service.known_peers
                and peer_address != full_node_service.local_address
            ):
                print(
                    f"Confirmed {peer_address} is valid. Adding {peer_address} to known peers",
                    flush=True,
                )
                full_node_service.known_peers.append(peer_address)

            for peer in response.knownPeers:
                if (
                    peer != full_node_service.local_address
                    and peer not in full_node_service.known_peers
                ):
                    print(
                        f"Adding received {peer} from {peer_address} to known peers.",
                        flush=True,
                    )
                    full_node_service.known_peers.append(peer)
                elif peer == full_node_service.local_address:
                    print(
                        f"Received own address {peer} in handshake response. Not adding.",
                        flush=True,
                    )
                elif peer in full_node_service.known_peers:
                    print(
                        f"Received peer: {peer} is already in known peers. Not adding.",
                        flush=True,
                    )
        except grpc.RpcError as e:
            print(f"Failed to perform handshake with {peer_address}: {e}", flush=True)


def wait_for_peers(full_node_service, expected_peer_count):
    while len(full_node_service.known_peers) < expected_peer_count:
        print(
            f"Waiting for peers... Currently known peers: {len(full_node_service.known_peers)}",
            flush=True,
        )
        time.sleep(2)
    print("All peers discovered! Ready to start mining.", flush=True)


def main():
    server, full_node_service, port = (
        serve()
    )  # Start the server and get the dynamically assigned port
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(
        f"Full Node started with IP address: {local_ip} and listening on port: {port}",
        flush=True,
    )

    last_peer = register_with_dns_seed(port)
    print(
        f"Registered with DNS_SEED. Last registered node IP from DNS_SEED: {last_peer}",
        flush=True,
    )
    if last_peer and last_peer != full_node_service.local_address:
        perform_handshake_with_peer(full_node_service, last_peer)

    # Handshake with all known peers
    for peer in full_node_service.known_peers:
        perform_handshake_with_peer(full_node_service, peer)

    # Assume the network consists of 3 nodes (including the current node)
    expected_peer_count = 2  # Number of other nodes expected in the network

    # Wait until all peers are known before starting mining
    wait_for_peers(full_node_service, expected_peer_count)

    # Start mining
    print("All peers discovered, starting mining...", flush=True)
    full_node_service.start()

    try:
        while True:
            time.sleep(86400)  # Keep the server running
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    main()
