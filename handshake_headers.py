from dataclasses import dataclass
import struct
from io import BytesIO

@dataclass
class HandshakeHeader:
    message_type: int
    size: int

    @classmethod
    def deserialize(klass, data: bytes):
        message_type = data[0]
        size, = struct.unpack(">i", b"\x00" + data[1:])
        return HandshakeHeader(message_type, size)

@dataclass
class HandshakePayload:
    data: bytes
    htype: int

    @classmethod
    def default_htype(klass) -> int:
        print("should not have been called!!!")
        raise NotImplementedError

    @classmethod
    def deserialize(klass, data: bytes):
        return klass(data=data, htype=klass.default_htype())

@dataclass
class ServerEncryptedExtensionHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return 0x08

@dataclass
class ServerCertificateHandshakePayload(HandshakePayload):
    certificate: bytes

    @classmethod
    def default_htype(klass) -> int:
        return 0x0b 

    @classmethod
    def deserialize(klass, data: bytes):
        bytes_buffer = BytesIO(data)
        _request_context, = struct.unpack("b", bytes_buffer.read(1))
        _certificate_length, = struct.unpack(">i", b"\x00" + bytes_buffer.read(3))
        certificate_length_follows, = struct.unpack(">i", b"\x00" + bytes_buffer.read(3))
        certificate = bytes_buffer.read(certificate_length_follows)
        _certificate_extensions_follow, = struct.unpack(">h", bytes_buffer.read(2))
        return ServerCertificateHandshakePayload(htype=klass.default_htype(), data=data, certificate=certificate)

@dataclass
class ServerCertificateVerifyHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return 0x0f

    @property
    def signature(self) -> bytes:
        return self.data

    # TODO: we need to varify the signature

@dataclass
class ServerHandshakeFinishedHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return 0x14

    @property
    def verify_data(self) -> bytes:
        return self.data

    # TODO: there maybe some more checks we want to do with the verify data as well...

HANDSHAKE_HEADER_TYPES = {
    ServerEncryptedExtensionHandshakePayload.default_htype(): ServerEncryptedExtensionHandshakePayload,
    ServerCertificateHandshakePayload.default_htype(): ServerCertificateHandshakePayload,
    ServerCertificateVerifyHandshakePayload.default_htype(): ServerCertificateVerifyHandshakePayload,
    ServerHandshakeFinishedHandshakePayload.default_htype(): ServerHandshakeFinishedHandshakePayload
}