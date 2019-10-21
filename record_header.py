import struct
from dataclasses import dataclass

@dataclass
class RecordHeader:
    rtype: int
    size: int
    legacy_proto_version: int = 0x0303

    @classmethod
    def deserialize(klass, data: bytes):
        record_type = data[0]
        legacy_proto_version, size = struct.unpack(">2h", data[1:])
        return RecordHeader(
            rtype=record_type, 
            legacy_proto_version=legacy_proto_version, 
            size=size)

    def serialize(self) -> bytes:
        return b"".join([
            struct.pack("b", self.rtype),
            struct.pack(">h", self.legacy_proto_version),
            struct.pack(">h", self.size),
        ])