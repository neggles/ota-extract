# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: puffin.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0cpuffin.proto\x12\x0fpuffin.metadata\"+\n\tBitExtent\x12\x0e\n\x06offset\x18\x01 \x01(\x04\x12\x0e\n\x06length\x18\x02 \x01(\x04\"z\n\nStreamInfo\x12,\n\x08\x64\x65\x66lates\x18\x01 \x03(\x0b\x32\x1a.puffin.metadata.BitExtent\x12)\n\x05puffs\x18\x02 \x03(\x0b\x32\x1a.puffin.metadata.BitExtent\x12\x13\n\x0bpuff_length\x18\x03 \x01(\x04\"\xcf\x01\n\x0bPatchHeader\x12\x0f\n\x07version\x18\x01 \x01(\x05\x12(\n\x03src\x18\x02 \x01(\x0b\x32\x1b.puffin.metadata.StreamInfo\x12(\n\x03\x64st\x18\x03 \x01(\x0b\x32\x1b.puffin.metadata.StreamInfo\x12\x34\n\x04type\x18\x04 \x01(\x0e\x32&.puffin.metadata.PatchHeader.PatchType\"%\n\tPatchType\x12\n\n\x06\x42SDIFF\x10\x00\x12\x0c\n\x08ZUCCHINI\x10\x01\x42\x02H\x03\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'puffin_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'H\003'
  _BITEXTENT._serialized_start=33
  _BITEXTENT._serialized_end=76
  _STREAMINFO._serialized_start=78
  _STREAMINFO._serialized_end=200
  _PATCHHEADER._serialized_start=203
  _PATCHHEADER._serialized_end=410
  _PATCHHEADER_PATCHTYPE._serialized_start=373
  _PATCHHEADER_PATCHTYPE._serialized_end=410
# @@protoc_insertion_point(module_scope)
