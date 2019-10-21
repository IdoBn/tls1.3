from dataclasses import dataclass
import struct
from io import BytesIO
from crypto import HKDF_Expand_Label
import hmac
import hashlib


@dataclass
class HandshakeHeader:
    message_type: int
    size: int

    @classmethod
    def deserialize(klass, data: bytes):
        message_type = data[0]
        size, = struct.unpack(">i", b"\x00" + data[1:])
        return HandshakeHeader(message_type, size)

    def serialize(self):
        return b"".join(
            [struct.pack("b", self.message_type), struct.pack(">i", self.size)[1:]]
        )


@dataclass
class HandshakePayload:
    data: bytes

    @classmethod
    def default_htype(klass) -> int:
        raise NotImplementedError

    @classmethod
    def deserialize(klass, data: bytes):
        return klass(data=data)


@dataclass
class EncryptedExtensionHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return 0x08


@dataclass
class CertificateHandshakePayload(HandshakePayload):
    certificate: bytes

    @classmethod
    def default_htype(klass) -> int:
        return 0x0B

    @classmethod
    def deserialize(klass, data: bytes):
        bytes_buffer = BytesIO(data)
        _request_context, = struct.unpack("b", bytes_buffer.read(1))
        _certificate_length, = struct.unpack(">i", b"\x00" + bytes_buffer.read(3))
        certificate_length_follows, = struct.unpack(
            ">i", b"\x00" + bytes_buffer.read(3)
        )
        certificate = bytes_buffer.read(certificate_length_follows)
        _certificate_extensions_follow, = struct.unpack(">h", bytes_buffer.read(2))
        return CertificateHandshakePayload(data=data, certificate=certificate)


@dataclass
class CertificateVerifyHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return 0x0F

    @property
    def signature(self) -> bytes:
        return self.data

    # TODO: we need to varify the signature


@dataclass
class HandshakeFinishedHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return 0x14

    @property
    def verify_data(self) -> bytes:
        return self.data

    @classmethod
    def generate(klass, client_handshake_traffic_secret: bytes, hello_hash: bytes):
        finished_key = HKDF_Expand_Label(
            key=client_handshake_traffic_secret,
            label="finished",
            context=b"",
            length=32,
        )
        verify_data = hmac.new(
            finished_key, msg=hello_hash, digestmod=hashlib.sha256
        ).digest()
        return HandshakeFinishedHandshakePayload(data=verify_data)

    # TODO: there maybe some more checks we want to do with the verify data as well...


HANDSHAKE_HEADER_TYPES = {
    EncryptedExtensionHandshakePayload.default_htype(): EncryptedExtensionHandshakePayload,
    CertificateHandshakePayload.default_htype(): CertificateHandshakePayload,
    CertificateVerifyHandshakePayload.default_htype(): CertificateVerifyHandshakePayload,
    HandshakeFinishedHandshakePayload.default_htype(): HandshakeFinishedHandshakePayload,
}
