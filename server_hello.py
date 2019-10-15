import struct
from dataclasses import dataclass
from client_hello import EXTENSIONS_MAP, ClientHelloExtension
from typing import List

@dataclass
class RecordHeader:
    rtype: int
    legacy_proto_version: int
    size: int

    @classmethod
    def deserialize(klass, data: bytes):
        record_type = data[0]
        legacy_proto_version, size = struct.unpack(">2h", data[1:])
        return RecordHeader(record_type, legacy_proto_version, size)

    @classmethod
    def required_bytes(klass):
        return 5


@dataclass
class HandshakeHeader:
    message_type: int
    size: int

    @classmethod
    def deserialize(klass, data: bytes):
        message_type = data[0]
        size, = struct.unpack(">h", data[2:])
        return HandshakeHeader(message_type, size)

    @classmethod
    def required_bytes(klass):
        return 4


class ServerHello:
    def __init__(self, 
                rh: RecordHeader, 
                hh: HandshakeHeader, 
                server_version: int, 
                server_random: bytes,
                session_id: bytes,
                cipher_suite: int,
                extensions: List[ClientHelloExtension]):
        self.record_header = rh
        self.handshake_header = hh
        self.server_version = server_version
        self.server_random = server_random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.extensions = extensions

    @classmethod
    def deserialize(klass, data: bytes):
        bytes_read = 0
        rh = RecordHeader.deserialize(data[:RecordHeader.required_bytes()])
        bytes_read += RecordHeader.required_bytes()
        hh = HandshakeHeader.deserialize(data[bytes_read:bytes_read + HandshakeHeader.required_bytes()])
        bytes_read += HandshakeHeader.required_bytes()
        server_version, = struct.unpack(">h", data[bytes_read:bytes_read+2])
        bytes_read += 2
        server_random = data[bytes_read:bytes_read+32]
        bytes_read += 32
        session_id_length = data[bytes_read]
        bytes_read += 1
        session_id = data[bytes_read:bytes_read+session_id_length]
        bytes_read += session_id_length
        cipher_suite, = struct.unpack(">h", data[bytes_read:bytes_read+2])
        bytes_read += 2
        _compression_mode = data[bytes_read]
        bytes_read += 1
        extensions_length, = struct.unpack(">h", data[bytes_read:bytes_read+2])
        bytes_read += 2
        
        extensions = []
        while extensions_length > 0:
            assigned_value, = struct.unpack(">h", data[bytes_read:bytes_read+2])
            extension_klass = EXTENSIONS_MAP[assigned_value]
            res = extension_klass.deserialize(data[bytes_read:])
            extensions.append(res)
            bytes_read += res.size + 2
            extensions_length -= res.size + 2

        return ServerHello(rh=rh, 
                            hh=hh, 
                            server_version=server_version, 
                            server_random=server_random, 
                            session_id=session_id,
                            cipher_suite=cipher_suite,
                            extensions=extensions)

        
            

