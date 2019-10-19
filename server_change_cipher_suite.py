from server_hello import RecordHeader
from io import BytesIO
from dataclasses import dataclass

@dataclass
class ServerChangeCipherSuite:
    record_header: RecordHeader
    payload: bytes

    @classmethod
    def deserialize(klass, byte_stream: BytesIO):
        rh = RecordHeader.deserialize(byte_stream.read(5))
        payload = byte_stream.read(rh.size)
        return ServerChangeCipherSuite(rh, payload)