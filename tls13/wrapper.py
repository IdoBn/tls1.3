from dataclasses import dataclass
from tls13.server_hello import RecordHeader
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

    def serialize(self):
        return b"".join([self.record_header.serialize(), self.payload])

    @property
    def auth_tag(self) -> bytes:
        return self.payload[-16:]

    @property
    def encrypted_data(self) -> bytes:
        return self.payload[:-16]
