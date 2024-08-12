import grpc
import health_service_pb2
import health_service_pb2_grpc
import dns_seed_pb2
import dns_seed_pb2_grpc
import time
import random
import socket
from concurrent import futures
import threading  # if we implement the mining functions
import db_models  # triggers the creation of the database
from db_models import HealthRecord, engine, Session
from sqlalchemy.orm import sessionmaker
import sqlite3
from problem2 import Blockchain
from problem2 import PatientDB
from problem2 import VerifiedAuthority
from problem2 import Transaction
from problem2 import Block
from problem2 import Requester
from problem2 import load_transactions_from_csv
from protoConvert import to_proto_transaction, from_proto_transaction, from_proto_block, to_proto_block


class Mempool:
    def __init__(self):
        self.transactions = []

    def add_transaction(self, transaction):
        #Add a transaction to the mempool.
        self.transactions.append(transaction)
        print(f"Transaction {transaction.TransactionHash} added to mempool", flush=True)

    def get_transactions(self):
        #Retrieve all transactions in the mempool.
        return self.transactions

    def remove_transaction(self, transaction_hash):
        #Remove a transaction from the mempool by its hash.
        self.transactions = [
            tx for tx in self.transactions if tx.TransactionHash != transaction_hash
        ]
        print(f"Transaction {transaction_hash} removed from mempool", flush=True)

    def clear_mempool(self):
        #Clear all transactions from the mempool.
        self.transactions = []
        print("Mempool cleared", flush=True)



class HealthNodeService(health_service_pb2_grpc.HealthServiceServicer):
    def __init__(self, session_factory):
        self.known_peers = []
        self.mempool = Mempool()  # TODO add mempool class
        self.patient_db = PatientDB() #an instance of the patient database to hole PatientWallet objects
        self.blockchain = Blockchain(self.patient_db) # TODO add blockchain class
        self.local_address = ""  #  Set after server starts
        # TODO add miner class?
        self.Session = session_factory
        self.completed_handshake = set()

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
        return health_service_pb2.HandshakeResponse(knownPeers=self.known_peers)

    # GRPC callable function that allows other nodes to share their new transactions to this node
    def NewTransactionBroadcast(self, request: health_service_pb2.NewTransactionRequest, context):
        transaction = request.newTransaction
        print(f"Received new transaction: {transaction.TransactionHash}", flush=True)

        if transaction.TransactionHash not in [
            tx.TransactionHash for tx in self.mempool.get_transactions()
        ]:
            self.mempool.add_transaction(from_proto_transaction(transaction))
            self.gossip_transaction(transaction)
        else:
           print(f"Transaction {transaction.TransactionHash} already in mempool.", flush=True)

        return health_service_pb2.Empty()
    
    def NewBlockBroadcast(self, request: health_service_pb2.NewBlockRequest, context):
        block = request.newBlock 
        
        peer_address = context.peer()
        peer_ip = peer_address.split(":")[1]
        print(f"Received new block from {peer_ip}: {block.Blockhash}", flush=True)

        if not block:
            self.blockchain.add_block(from_proto_block(block))
            self.gossip_block(block)
            
        # Random sleep to reduce chance of simultaneous mining
        time.sleep(random.randint(0, 3))

        return health_service_pb2.Empty()

    def gossip_transaction(self, request: health_service_pb2.NewTransactionRequest):
        transaction = request.newTransaction
        print(
            f"Gossiping transaction {transaction.TransactionHash} to peers: {self.known_peers}",
            flush=True,
        )
        for peer in self.known_peers:
            ip, port = peer.split(":")
            with grpc.insecure_channel(f"{ip}:{port}") as channel:
                stub = health_service_pb2_grpc.HealthServiceStub(channel)
                try:
                    stub.NewTransactionBroadcast(request)
                except grpc.RpcError as e:
                    print(f"Failed to broadcast transaction to {peer}: {e}", flush=True)

    def gossip_block(self, request: health_service_pb2.NewBlockRequest):
        block = request.newBlock
        print(
            f"Gossiping block {block.Blockhash} to peers: {self.known_peers}",
            flush=True,
        )
        for peer in self.known_peers:
            ip, port = peer.split(":")
            with grpc.insecure_channel(f"{ip}:{port}") as channel:
                stub = health_service_pb2_grpc.HealthServiceStub(channel)
                try:
                    stub.NewBlockBroadcast(
                        health_service_pb2.NewBlockRequest(newBlock=block)
                    )
                except grpc.RpcError as e:
                    print(f"Failed to broadcast block to {peer}: {e}", flush=True)

    # These MUST be named the same thing as in the proto file!
    def getUserRecordAccessResearcherToUser(self, request, context):
        response = health_service_pb2.ReponseUserRecordAccessUserToResearcher()

        # TODO: populate with actual data from blockchain classes
        response.patient_blockchain_address = "1"
        response.signed_data_request = "2"
        return response

    def getUserRecordAccessResearcherToVO(self, request, context):
        response = health_service_pb2.ResponseUserRecordAccessVOToResearcher()
        patient_blockchain_address = request.patient_blockchain_address
        signed_data_request = request.signed_data_request
        jwt_token = request.jwt_token
        return response

    def sendUserAuthTokenToResearcher(self, request, context):
        patient_blockchain_address = request.patient_blockchain_address
        jwt_token = request.jwt_token
        response = health_service_pb2.ConfirmUserAuthTokenResearcherToUser()
        response.success = True
        return response

    def sendUserAuthTokenToVO(self, request, context):
        patient_blockchain_address = request.patient_blockchain_address
        jwt_token = request.jwt_token
        response = health_service_pb2.ConfirmUserAuthTokenVOToUser()
        response.success = True
        return response

    def getHealthRecordsFromDB(self, request, context):
        session = self.Session()
        records = session.query(HealthRecord).all()
        session.close()
        if records:
            return health_service_pb2.GetHealthRecordsResponse(records=records)
        else:
            context.abort(grpc.StatusCode.NOT_FOUND, "No records found")


## Utility functions to register with DNS_SEED and perform handshake with peers
def register_with_dns_seed(port):
    # Use socket to get the current IP address of the host
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    with grpc.insecure_channel("dns_health_seed:12345") as channel:
        stub = dns_seed_pb2_grpc.RegistrarStub(channel)
        response = stub.RegisterNode(
            dns_seed_pb2.RegistrationRequest(
                version="1.0",
                time=str(time.time()),
                addrMe=f"{local_ip}:{port}",  # Register with the IP and dynamically assigned port
            )
        )
        return response.last_registered_node


def perform_handshake_with_peer(health_node_service, peer_address):
    ip, port = peer_address.split(":")
    with grpc.insecure_channel(f"{ip}:{port}") as channel:
        stub = health_service_pb2_grpc.HealthServiceStub(channel)
        try:
            print(f"Calling handshake function on {peer_address}", flush=True)
            response = stub.Handshake(
                health_service_pb2.HandshakeRequest(
                    version="1.0",
                    time=str(time.time()),
                    addrMe=health_node_service.local_address,
                    # TODO: change this to the height of the blockchain
                    bestHeight=1,
                    # bestHeight=len(
                    #     health_node_service.blockchain.chain
                    # ),  # Example blockchain height
                )
            )

            print(
                f"Handshake with {peer_address} succeeded. Known peers received: {response.knownPeers}.",
                flush=True,
            )
            if (
                peer_address not in health_node_service.known_peers
                and peer_address != health_node_service.local_address
            ):
                print(
                    f"Confirmed {peer_address} is valid. Adding {peer_address} to known peers",
                    flush=True,
                )
                health_node_service.known_peers.append(peer_address)

            for peer in response.knownPeers:
                if (
                    peer != health_node_service.local_address
                    and peer not in health_node_service.known_peers
                ):
                    print(
                        f"Adding received {peer} from {peer_address} to known peers.",
                        flush=True,
                    )
                    health_node_service.known_peers.append(peer)
                elif peer == health_node_service.local_address:
                    print(
                        f"Received own address {peer} in handshake response. Not adding.",
                        flush=True,
                    )
                elif peer in health_node_service.known_peers:
                    print(
                        f"Received peer: {peer} is already in known peers. Not adding.",
                        flush=True,
                    )
        except grpc.RpcError as e:
            print(f"Failed to perform handshake with {peer_address}: {e}", flush=True)


# Function to start the server
def serve():

    # Create DB session factory to make DB requests
    session_factory = sessionmaker(bind=engine)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    health_node_service = HealthNodeService(session_factory)
    health_service_pb2_grpc.add_HealthServiceServicer_to_server(
        health_node_service, server
    )
    port = server.add_insecure_port("[::]:0")
    server.start()

    # Set the dynamically assigned port in the FullNodeService instance
    health_node_service.local_address = (
        f"{socket.gethostbyname(socket.gethostname())}:{port}"
    )

    return server, health_node_service, port


def main():
    # Starting the server and getting the ip and assigned port 
    server, health_node_service, port = (
        serve()
    )  
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print(
        f"Full Node started with IP address: {local_ip} and listening on port: {port}",
        flush=True,
    )

    # Registering with the DNS by calling the dns-seed's register function
    last_peer = register_with_dns_seed(port)
    print(
        f"Registered with DNS_SEED. Last registered node IP from DNS_SEED: {last_peer}",
        flush=True,
    )

    # Checking if the received ip is new 
    if last_peer and last_peer != health_node_service.local_address and last_peer not in health_node_service.completed_handshake:
        perform_handshake_with_peer(health_node_service, last_peer)
        health_node_service.completed_handshake.add(last_peer)

    # Handshake with all known peers that we haven't shaken hands with
    for peer in health_node_service.known_peers:
        if peer not in health_node_service.completed_handshake:
            perform_handshake_with_peer(health_node_service, peer)
            health_node_service.completed_handshake.add(peer)

    
    #in this version we are just creating 1 VO object
    vo = VerifiedAuthority()
    #and also only 1 requestor for approval
    requester = Requester()
    
    #build transactions from the csv file
    transactions = load_transactions_from_csv("MOCK_DATA.csv", health_node_service.patient_db, vo)

    # test gossip a transaction 
    health_node_service.gossip_transaction(health_service_pb2.NewTransactionRequest(
                            newTransaction=to_proto_transaction(transactions[0])
                    ))
    
    # create test block
    block_1 = Block(transactions[:5])
    block_2 = Block(transactions[5:10])
    
    health_node_service.blockchain.add_block(block_1)
    # test gossip a block
    health_node_service.gossip_block(health_service_pb2.NewBlockRequest(
                            newBlock=to_proto_block(block_1)
                    ))
    
    health_node_service.blockchain.add_block(block_2)
    # test gossip a block
    health_node_service.gossip_block(health_service_pb2.NewBlockRequest(
                            newBlock=to_proto_block(block_1)
                    ))


    # print("\nPrinting all transactions associated with a given patient address")
    # b.print_patient_transactions(transactions[0].PatientAddress)

    # #print("\nPrinting summary of transactions associated with a given HIPAA ID")
    # #b.print_hippa_summary(transactions[0].HippaID)

    # print("\nTesting the app_sig function")
    # print("\nFirst search for the transactions with Hippa ID 103 (the first one is the one that has just been printed to the terminal)")
    # hippa103 = b.search_hippa_transactions(103)
    # print("\ntake that tx and lets simulate a patient giving approval to the requestor")
    # #first i create a new Transaction as i dont want to amend the original, but it replicates all the original fields
    # approval_tx = Transaction(hippa103[0].PatientAddress, hippa103[0].VOAddress, hippa103[0].HippaID, hippa103[0].SummaryAvail, hippa103[0].Data)
    # health_node_service.NewTransactionBroadcast(approval_tx)
    # #then we add the 2 new fields and rehash it to complete the approved transaction
    # approval_tx.req_approval(requester)
    # print("\nprint the new updated transaction with new RequestorAddress, Approval and Hash\n")
    # approval_tx.printTransaction()
    # print("\nnow lets confirm it returns the correct database id from the MOCK_DATA.csv\n")
    # vo_submission = requester.requestor_generate(approval_tx.Approval)
    # retrieved_record_id = vo.vo_verify(vo_submission)
    # print("Retrieved Record ID:", retrieved_record_id)
    
    try:
        while True:
            time.sleep(86400)  # Keep the server running
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    main()
