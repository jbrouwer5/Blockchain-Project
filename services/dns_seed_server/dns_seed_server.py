import grpc
from concurrent import futures
import time
import socket
import dns_seed_pb2
import dns_seed_pb2_grpc


class RegistrarService(dns_seed_pb2_grpc.RegistrarServicer):
    def __init__(self):
        self.last_registered_node = None

    def RegisterNode(self, request, context):
        current_node = request.addrMe
        print(f"Received registration from {current_node}")

        # Retrieve the last registered node (could be None if this is the first node)
        last_node = self.last_registered_node

        # Update the last registered node to the current node
        self.last_registered_node = current_node

        # If this is the first node, last_node will be None
        if last_node is None:
            print(f"This is the first node. No other nodes to connect to.")
        else:
            print(f"Sending the last registered node to the FULL_NODE: {last_node}")

        # Return the last registered node (could be None if first node)
        print(f"Returning the last registered node: {last_node}")
        return dns_seed_pb2.RegistrationResponse(last_registered_node=last_node)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    dns_seed_pb2_grpc.add_RegistrarServicer_to_server(RegistrarService(), server)
    server.add_insecure_port("[::]:12345")
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"DNS_SEED gRPC server started on {local_ip}:12345")
    server.start()

    try:
        while True:
            time.sleep(86400)  # Keep the server running
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    serve()
