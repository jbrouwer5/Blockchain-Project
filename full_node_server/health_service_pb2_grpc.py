# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

import health_service_pb2 as health__service__pb2

GRPC_GENERATED_VERSION = '1.65.4'
GRPC_VERSION = grpc.__version__
EXPECTED_ERROR_RELEASE = '1.66.0'
SCHEDULED_RELEASE_DATE = 'August 6, 2024'
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    warnings.warn(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in health_service_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
        + f' This warning will become an error in {EXPECTED_ERROR_RELEASE},'
        + f' scheduled for release on {SCHEDULED_RELEASE_DATE}.',
        RuntimeWarning
    )


class HealthServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.getUserRecordAccessResearcherToUser = channel.unary_unary(
                '/healthservice.HealthService/getUserRecordAccessResearcherToUser',
                request_serializer=health__service__pb2.RequestUserRecordAccessResearcherToUser.SerializeToString,
                response_deserializer=health__service__pb2.ResponseUserRecordAccessUserToResearcher.FromString,
                _registered_method=True)
        self.getUserRecordAccessResearcherToVO = channel.unary_unary(
                '/healthservice.HealthService/getUserRecordAccessResearcherToVO',
                request_serializer=health__service__pb2.RequestUserRecordAccessResearcherToVO.SerializeToString,
                response_deserializer=health__service__pb2.ResponseUserRecordAccessVOToResearcher.FromString,
                _registered_method=True)
        self.sendUserAuthTokenToResearcher = channel.unary_unary(
                '/healthservice.HealthService/sendUserAuthTokenToResearcher',
                request_serializer=health__service__pb2.SendUserAuthTokenToResearcher.SerializeToString,
                response_deserializer=health__service__pb2.ConfirmUserAuthTokenResearcherToUser.FromString,
                _registered_method=True)
        self.sendUserAuthTokenToVO = channel.unary_unary(
                '/healthservice.HealthService/sendUserAuthTokenToVO',
                request_serializer=health__service__pb2.SendUserAuthTokenToVO.SerializeToString,
                response_deserializer=health__service__pb2.ConfirmUserAuthTokenVOToUser.FromString,
                _registered_method=True)
        self.getHealthRecords = channel.unary_unary(
                '/healthservice.HealthService/getHealthRecords',
                request_serializer=health__service__pb2.GetHealthRecordsRequest.SerializeToString,
                response_deserializer=health__service__pb2.HealthRecordListResponse.FromString,
                _registered_method=True)
        self.Handshake = channel.unary_unary(
                '/healthservice.HealthService/Handshake',
                request_serializer=health__service__pb2.HandshakeRequest.SerializeToString,
                response_deserializer=health__service__pb2.HandshakeResponse.FromString,
                _registered_method=True)
        self.NewTransactionBroadcast = channel.unary_unary(
                '/healthservice.HealthService/NewTransactionBroadcast',
                request_serializer=health__service__pb2.NewTransactionRequest.SerializeToString,
                response_deserializer=health__service__pb2.Empty.FromString,
                _registered_method=True)
        self.NewBlockBroadcast = channel.unary_unary(
                '/healthservice.HealthService/NewBlockBroadcast',
                request_serializer=health__service__pb2.NewBlockRequest.SerializeToString,
                response_deserializer=health__service__pb2.Empty.FromString,
                _registered_method=True)


class HealthServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def getUserRecordAccessResearcherToUser(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def getUserRecordAccessResearcherToVO(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def sendUserAuthTokenToResearcher(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def sendUserAuthTokenToVO(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def getHealthRecords(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Handshake(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def NewTransactionBroadcast(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def NewBlockBroadcast(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_HealthServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'getUserRecordAccessResearcherToUser': grpc.unary_unary_rpc_method_handler(
                    servicer.getUserRecordAccessResearcherToUser,
                    request_deserializer=health__service__pb2.RequestUserRecordAccessResearcherToUser.FromString,
                    response_serializer=health__service__pb2.ResponseUserRecordAccessUserToResearcher.SerializeToString,
            ),
            'getUserRecordAccessResearcherToVO': grpc.unary_unary_rpc_method_handler(
                    servicer.getUserRecordAccessResearcherToVO,
                    request_deserializer=health__service__pb2.RequestUserRecordAccessResearcherToVO.FromString,
                    response_serializer=health__service__pb2.ResponseUserRecordAccessVOToResearcher.SerializeToString,
            ),
            'sendUserAuthTokenToResearcher': grpc.unary_unary_rpc_method_handler(
                    servicer.sendUserAuthTokenToResearcher,
                    request_deserializer=health__service__pb2.SendUserAuthTokenToResearcher.FromString,
                    response_serializer=health__service__pb2.ConfirmUserAuthTokenResearcherToUser.SerializeToString,
            ),
            'sendUserAuthTokenToVO': grpc.unary_unary_rpc_method_handler(
                    servicer.sendUserAuthTokenToVO,
                    request_deserializer=health__service__pb2.SendUserAuthTokenToVO.FromString,
                    response_serializer=health__service__pb2.ConfirmUserAuthTokenVOToUser.SerializeToString,
            ),
            'getHealthRecords': grpc.unary_unary_rpc_method_handler(
                    servicer.getHealthRecords,
                    request_deserializer=health__service__pb2.GetHealthRecordsRequest.FromString,
                    response_serializer=health__service__pb2.HealthRecordListResponse.SerializeToString,
            ),
            'Handshake': grpc.unary_unary_rpc_method_handler(
                    servicer.Handshake,
                    request_deserializer=health__service__pb2.HandshakeRequest.FromString,
                    response_serializer=health__service__pb2.HandshakeResponse.SerializeToString,
            ),
            'NewTransactionBroadcast': grpc.unary_unary_rpc_method_handler(
                    servicer.NewTransactionBroadcast,
                    request_deserializer=health__service__pb2.NewTransactionRequest.FromString,
                    response_serializer=health__service__pb2.Empty.SerializeToString,
            ),
            'NewBlockBroadcast': grpc.unary_unary_rpc_method_handler(
                    servicer.NewBlockBroadcast,
                    request_deserializer=health__service__pb2.NewBlockRequest.FromString,
                    response_serializer=health__service__pb2.Empty.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'healthservice.HealthService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('healthservice.HealthService', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class HealthService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def getUserRecordAccessResearcherToUser(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/healthservice.HealthService/getUserRecordAccessResearcherToUser',
            health__service__pb2.RequestUserRecordAccessResearcherToUser.SerializeToString,
            health__service__pb2.ResponseUserRecordAccessUserToResearcher.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def getUserRecordAccessResearcherToVO(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/healthservice.HealthService/getUserRecordAccessResearcherToVO',
            health__service__pb2.RequestUserRecordAccessResearcherToVO.SerializeToString,
            health__service__pb2.ResponseUserRecordAccessVOToResearcher.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def sendUserAuthTokenToResearcher(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/healthservice.HealthService/sendUserAuthTokenToResearcher',
            health__service__pb2.SendUserAuthTokenToResearcher.SerializeToString,
            health__service__pb2.ConfirmUserAuthTokenResearcherToUser.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def sendUserAuthTokenToVO(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/healthservice.HealthService/sendUserAuthTokenToVO',
            health__service__pb2.SendUserAuthTokenToVO.SerializeToString,
            health__service__pb2.ConfirmUserAuthTokenVOToUser.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def getHealthRecords(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/healthservice.HealthService/getHealthRecords',
            health__service__pb2.GetHealthRecordsRequest.SerializeToString,
            health__service__pb2.HealthRecordListResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Handshake(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/healthservice.HealthService/Handshake',
            health__service__pb2.HandshakeRequest.SerializeToString,
            health__service__pb2.HandshakeResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def NewTransactionBroadcast(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/healthservice.HealthService/NewTransactionBroadcast',
            health__service__pb2.NewTransactionRequest.SerializeToString,
            health__service__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def NewBlockBroadcast(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/healthservice.HealthService/NewBlockBroadcast',
            health__service__pb2.NewBlockRequest.SerializeToString,
            health__service__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
