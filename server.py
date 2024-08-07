import grpc
from concurrent import futures
import service_pb2
import service_pb2_grpc


# Define a class to implement the server methods
class MyServiceServicer(service_pb2_grpc.MyServiceServicer):

    # Define the SayHello method and the GetBlockID method
    # These MUST be named the same thing as in the proto file!
    def SayHello(self, request, context):
        response = service_pb2.ResponseMessage()
        response.message = f"Hello, {request.name}!"
        return response

    def GetBlockID(self, request, context):
        response = service_pb2.ResponseBlockID()
        response.message = f"{request.blockId}"
        return response


# Function to start the server
def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    service_pb2_grpc.add_MyServiceServicer_to_server(MyServiceServicer(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Server started on port 50051")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
