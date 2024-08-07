import grpc
from concurrent import futures
import health_service_pb2
import health_service_pb2_grpc


# Define a class to implement the server methods
class HealthServiceServicer(health_service_pb2_grpc.HealthServiceServicer):

    # Define the SayHello method and the GetBlockID method
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


# Function to start the server
def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    health_service_pb2_grpc.add_HealthServiceServicer_to_server(
        HealthServiceServicer(), server
    )
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Server started on port 50051")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
