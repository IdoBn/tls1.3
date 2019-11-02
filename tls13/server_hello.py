import struct
from dataclasses import dataclass
from tls13.client_hello import EXTENSIONS_MAP, ClientHelloExtension
from typing import List
from io import BufferedReader
from tls13.handshake_headers import HandshakeHeader
from tls13.record_header import RecordHeader


class ServerHello:
    def __init__(
        self,
        rh: RecordHeader,
        hh: HandshakeHeader,
        server_version: int,
        server_random: bytes,
        session_id: bytes,
        cipher_suite: int,
        extensions: List[ClientHelloExtension],
    ):
        self.record_header = rh
        self.handshake_header = hh
        self.server_version = server_version
        self.server_random = server_random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.extensions = extensions

    @classmethod
    def deserialize(klass, byte_stream: BufferedReader):
        rh = RecordHeader.deserialize(byte_stream.read(5))
        hh = HandshakeHeader.deserialize(byte_stream.read(4))
        server_version, = struct.unpack(">h", byte_stream.read(2))
        server_random = byte_stream.read(32)
        session_id_length, = struct.unpack("b", byte_stream.read(1))
        session_id = byte_stream.read(session_id_length)
        cipher_suite, = struct.unpack(">h", byte_stream.read(2))
        _compression_mode = byte_stream.read(1)
        extensions_length, = struct.unpack(">h", byte_stream.read(2))

        extensions = []
        while extensions_length > 0:
            assigned_value, = struct.unpack(">h", byte_stream.peek()[:2])
            extension_klass = EXTENSIONS_MAP[assigned_value]
            res = extension_klass.deserialize(byte_stream)
            extensions.append(res)
            extensions_length -= res.size + 2

        return ServerHello(
            rh=rh,
            hh=hh,
            server_version=server_version,
            server_random=server_random,
            session_id=session_id,
            cipher_suite=cipher_suite,
            extensions=extensions,
        )
