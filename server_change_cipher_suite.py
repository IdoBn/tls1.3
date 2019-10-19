from server_hello import RecordHeader
from io import BytesIO

class ServerChangeCipherSuite:
    def __init__(self,
                rh: RecordHeader,
                payload: bytes):
        self.record_header = rh
        self.payload = payload

    @classmethod
    def deserialize(klass, data: bytes):
        byte_stream = BytesIO(data)
        rh = RecordHeader.deserialize(byte_stream.read(5))
        payload = byte_stream.read(rh.size)
        return ServerChangeCipherSuite(rh, payload)