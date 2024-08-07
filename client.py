import grpc
import health_service_pb2
import health_service_pb2_grpc


def run():
    # Connect to the server
    channel = grpc.insecure_channel("localhost:50051")
    stub = health_service_pb2_grpc.HealthServiceStub(channel)

    # Create a request
    # service_pb2.<method>
    # corresponds to the rpc data structures defined in the protofile
    # i.e. message <data structure> {string <parameter name>}
    # the parameters for the requests below are defined in the proto file
    request = health_service_pb2.RequestUserRecordAccessResearcherToUser(
        patient_blockchain_address="0x1234567890"
    )
    print("Request:", request)
    response = stub.sendUserAuthTokenToResearcher(request)
    print("Response:", response)


if __name__ == "__main__":
    run()
