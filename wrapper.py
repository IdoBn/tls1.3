from dataclasses import dataclass
from server_hello import RecordHeader
from io import BytesIO

@dataclass
class Wrapper:
    record_header: RecordHeader
    payload: bytearray

    @classmethod
    def deserialize(klass, byte_stream: BytesIO):
        rh = RecordHeader.deserialize(byte_stream.read(5))
        payload = bytearray(byte_stream.read(rh.size))
        return Wrapper(rh, payload)