# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: full_node.proto
# Protobuf Python Version: 5.26.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0f\x66ull_node.proto\"U\n\x10HandshakeRequest\x12\x0f\n\x07version\x18\x01 \x01(\t\x12\x0c\n\x04time\x18\x02 \x01(\t\x12\x0e\n\x06\x61\x64\x64rMe\x18\x03 \x01(\t\x12\x12\n\nbestHeight\x18\x04 \x01(\x05\"\'\n\x11HandshakeResponse\x12\x12\n\nknownPeers\x18\x01 \x03(\t\"1\n\x15NewTransactionRequest\x12\x18\n\x10transaction_data\x18\x01 \x01(\t\"%\n\x0fNewBlockRequest\x12\x12\n\nblock_data\x18\x01 \x01(\t\"\x07\n\x05\x45mpty2\xa8\x01\n\x08\x46ullNode\x12\x32\n\tHandshake\x12\x11.HandshakeRequest\x1a\x12.HandshakeResponse\x12\x39\n\x17NewTransactionBroadcast\x12\x16.NewTransactionRequest\x1a\x06.Empty\x12-\n\x11NewBlockBroadcast\x12\x10.NewBlockRequest\x1a\x06.Emptyb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'full_node_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_HANDSHAKEREQUEST']._serialized_start=19
  _globals['_HANDSHAKEREQUEST']._serialized_end=104
  _globals['_HANDSHAKERESPONSE']._serialized_start=106
  _globals['_HANDSHAKERESPONSE']._serialized_end=145
  _globals['_NEWTRANSACTIONREQUEST']._serialized_start=147
  _globals['_NEWTRANSACTIONREQUEST']._serialized_end=196
  _globals['_NEWBLOCKREQUEST']._serialized_start=198
  _globals['_NEWBLOCKREQUEST']._serialized_end=235
  _globals['_EMPTY']._serialized_start=237
  _globals['_EMPTY']._serialized_end=244
  _globals['_FULLNODE']._serialized_start=247
  _globals['_FULLNODE']._serialized_end=415
# @@protoc_insertion_point(module_scope)
