import grpc
import service_pb2
import service_pb2_grpc


def run():
    # Connect to the server
    channel = grpc.insecure_channel("localhost:50051")
    stub = service_pb2_grpc.MyServiceStub(channel)

    # Create a request
    # service_pb2.<method>
    # corresponds to the rpc data structures defined in the protofile
    # i.e. message <data structure> {string <parameter name>}
    # the parameters for the requests below are defined in the proto file

    request = service_pb2.RequestMessage(name="World")
    requestBlockID = service_pb2.RequestBlockID(blockId="2")

    # Call the SayHello method

    # the stub is like a class
    # that calls the rpc method in th service defined in the proto file.
    # ex. stub.SayHello(request) corresponds to
    # rpc SayHello(RequestMessage) returns (ResponseMessage);
    response = stub.SayHello(request)
    print("Received message:", response.message)
    requestBlockID = stub.GetBlockID(requestBlockID)
    print("Received blockID:", requestBlockID.message)


if __name__ == "__main__":
    run()
