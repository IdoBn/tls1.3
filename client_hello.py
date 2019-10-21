import struct
import secrets
from record_header import RecordHeader
from handshake_headers import HandshakeHeader

EXTENSION_SERVER_NAME = 0x00
EXTENSION_SUPPORTED_GROUPS = 0x0A
EXTENSION_SIGNATURE_ALGORITHMS = 0x0D
EXTENSION_KEY_SHARE = 0x33
EXTENSION_PSK_KEY_EXCHANGE_MODES = 0x2D
EXTENSION_SUPPORTED_VERSIONS = 0x2B


class ClientHelloExtension:
    def __init__(self, assigned_value, data):
        self.assigned_value = assigned_value
        self.size = len(data) + 2
        self.some_other_size = len(data)
        self.data = data

    def serialize(self) -> bytes:
        return b"".join(
            [
                struct.pack(">h", self.assigned_value),
                struct.pack(">h", self.size),
                struct.pack(">h", self.some_other_size),
                self.data,
            ]
        )


class ExtensionServerName(ClientHelloExtension):
    def __init__(self, server_name):
        data = b"".join(
            [struct.pack("b", 0), struct.pack(">h", len(server_name)), server_name]
        )
        super().__init__(EXTENSION_SERVER_NAME, data)


class ExtensionSupportedGroups(ClientHelloExtension):
    def __init__(self):
        supported_groups = [0x1D, 0x17, 0x18]  # x25519  # x25519  # x25519
        data = b"".join([struct.pack(">h", group) for group in supported_groups])
        super().__init__(EXTENSION_SUPPORTED_GROUPS, data)


class ExtensionSignatureAlgorithms(ClientHelloExtension):
    def __init__(self):
        supported_signatures = [
            0x0403,  # ECDSA-SECP256r1-SHA256
            0x0804,  # RSA-PSS-RSAE-SHA256
            0x0401,  # RSA-PKCS1-SHA256
            0x0503,  # ECDSA-SECP384r1-SHA384
            0x0805,  # RSA-PSS-RSAE-SHA384
            0x0501,  # RSA-PKCS1-SHA386
            0x0806,  # RSA-PSS-RSAE-SHA512
            0x0601,  # RSA-PKCS1-SHA512
            0x0201,  # RSA-PKCS1-SHA1
        ]
        data = b"".join([struct.pack(">h", group) for group in supported_signatures])
        super().__init__(EXTENSION_SIGNATURE_ALGORITHMS, data)


class ExtensionKeyShare(ClientHelloExtension):
    def __init__(self, public_key_bytes: bytes):
        self.public_key_bytes = public_key_bytes
        data = b"".join(
            [
                struct.pack(">h", 0x001D),
                struct.pack(">h", len(public_key_bytes)),
                public_key_bytes,
            ]
        )
        super().__init__(EXTENSION_KEY_SHARE, data)

    @classmethod
    def deserialize(klass, data):
        _assigned_value, = struct.unpack(">h", data.read(2))
        _data_follows, = struct.unpack(">h", data.read(2))
        _x25519_assigned_value, = struct.unpack(">h", data.read(2))
        public_key_length, = struct.unpack(">h", data.read(2))
        public_key_bytes = data.read(public_key_length)
        return ExtensionKeyShare(public_key_bytes)


class ExtensionPSKKeyExchangeModes(ClientHelloExtension):
    def __init__(self):
        pass

    def serialize(self) -> bytes:
        data = b"".join(
            [
                struct.pack(">h", EXTENSION_PSK_KEY_EXCHANGE_MODES),
                struct.pack(">h", 0x02),
                struct.pack("b", 0x01),
                struct.pack("b", 0x01),
            ]
        )
        return data


class ExtensionSupportedVersions(ClientHelloExtension):
    def __init__(self):
        self.size = 4
        self.data = 0x0304

    def serialize(self) -> bytes:
        data = b"".join(
            [
                struct.pack(">h", EXTENSION_SUPPORTED_VERSIONS),
                struct.pack(">h", 0x03),
                struct.pack("b", 0x02),
                struct.pack(">h", self.data),
            ]
        )
        return data

    @classmethod
    def deserialize(klass, data):
        _assigned_value, = struct.unpack(">h", data.read(2))
        _data_follows, = struct.unpack(">h", data.read(2))
        _assigned_version, = struct.unpack(">h", data.read(2))
        return ExtensionSupportedVersions()


EXTENSIONS_MAP = {
    EXTENSION_SERVER_NAME: ExtensionServerName,
    EXTENSION_SUPPORTED_GROUPS: ExtensionSupportedGroups,
    EXTENSION_SIGNATURE_ALGORITHMS: ExtensionSignatureAlgorithms,
    EXTENSION_KEY_SHARE: ExtensionKeyShare,
    EXTENSION_PSK_KEY_EXCHANGE_MODES: ExtensionPSKKeyExchangeModes,
    EXTENSION_SUPPORTED_VERSIONS: ExtensionSupportedVersions,
}


class ClientHello:
    def __init__(self, domain: bytes, public_key_bytes: bytes):
        self.record_header = RecordHeader(
            rtype=0x16, legacy_proto_version=0x0301, size=0
        )
        self.handshake_header = HandshakeHeader(message_type=0x01, size=0)
        self.client_version = 0x0303
        self.client_random = secrets.token_bytes(32)
        self.session_id = secrets.token_bytes(32)
        # hard coded for now...
        # 13 01 - assigned value for TLS_AES_128_GCM_SHA256
        # 13 02 - assigned value for TLS_AES_256_GCM_SHA384
        # 13 03 - assigned value for TLS_CHACHA20_POLY1305_SHA256
        self.cipher_suites = bytes.fromhex("130113021303")

        extensions = [
            ExtensionServerName(domain),
            ExtensionSupportedGroups(),
            ExtensionSignatureAlgorithms(),
            ExtensionKeyShare(public_key_bytes),
            ExtensionPSKKeyExchangeModes(),
            ExtensionSupportedVersions(),
        ]

        self.extension_data = b"".join([ex.serialize() for ex in extensions])
        self.extension_length = len(self.extension_data)

    def calc_record_size(self) -> int:
        data = self._serialize()
        self.record_header.size = len(data) - 5
        self.handshake_header.size = self.record_header.size - 4

    def _serialize(self) -> bytes:
        return b"".join(
            [
                self.record_header.serialize(),
                self.handshake_header.serialize(),
                struct.pack(">h", self.client_version),
                struct.pack("32s", self.client_random),
                struct.pack("b32s", len(self.session_id), self.session_id),
                struct.pack(
                    f">h{len(self.cipher_suites)}s",
                    len(self.cipher_suites),
                    self.cipher_suites,
                ),
                struct.pack("bb", 1, 0),  # compression mode
                struct.pack(">h", self.extension_length),
                self.extension_data,
            ]
        )

    def serialize(self) -> bytes:
        self.calc_record_size()
        return self._serialize()
