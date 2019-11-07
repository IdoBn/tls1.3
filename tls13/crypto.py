from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from dataclasses import dataclass
import hashlib
import struct


def xor_iv(iv, num):
    formatted_num = (b"\x00" * 4) + struct.pack(">q", num)
    return bytes([i ^ j for i, j in zip(iv, formatted_num)])


def HKDF_Expand_Label(
    key, label, context, length, backend=default_backend(), algorithm=hashes.SHA256()
):
    tmp_label = b"tls13 " + label.encode()
    hkdf_label = (
        struct.pack(">h", length)
        + struct.pack("b", len(tmp_label))
        + tmp_label
        + struct.pack("b", len(context))
        + context
    )
    return HKDFExpand(
        algorithm=algorithm, length=length, info=hkdf_label, backend=backend
    ).derive(key)


@dataclass
class ApplicationKeys:
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes
    resumption_master_secret: bytes


@dataclass
class HandshakeKeys:
    client_key: bytes
    client_iv: bytes
    client_handshake_traffic_secret: bytes
    server_key: bytes
    server_iv: bytes
    server_handshake_traffic_secret: bytes
    handshake_secret: bytes


@dataclass
class ResumptionKeys:
    binder_key: bytes
    early_secret: bytes


@dataclass
class KeyPair:
    private_key: X25519PrivateKey

    @property
    def public(self) -> bytes:
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return public_bytes

    @property
    def private(self) -> bytes:
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_bytes

    def exchange(self, peer_pub_key_bytes: bytes) -> bytes:
        peer_pub_key = X25519PublicKey.from_public_bytes(peer_pub_key_bytes)
        shared_key = self.private_key.exchange(peer_pub_key)
        return shared_key

    def derive_early_keys(self, psk: bytes, client_hello_hash: bytes) -> ResumptionKeys:
        backend=default_backend()
        early_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"\x00",
            salt=b"\x00",
            backend=backend,
        )._extract(psk)
        empty_hash = hashlib.sha256(b"").digest()
        binder_key = HKDF_Expand_Label(
            key=early_secret,
            algorithm=hashes.SHA256(),
            length=32,
            label="res binder",
            context=empty_hash,
            backend=backend,
        )
        client_early_traffic_secret = HKDF_Expand_Label(
            key=early_secret,
            algorithm=hashes.SHA256(),
            length=32,
            label="c e traffic",
            context=client_hello_hash,
            backend=backend,
        )
        early_exporter_master_secret = HKDF_Expand_Label(
            key=early_secret,
            algorithm=hashes.SHA256(),
            length=32,
            label="e exp master",
            context=client_hello_hash,
            backend=backend,
        )
        return ResumptionKeys(
            binder_key=binder_key,
            early_secret=early_secret,
        )


    def derive(self, shared_secret: bytes, hello_hash: bytes, resumption_keys: ResumptionKeys=None):
        backend = default_backend()
        if resumption_keys:
            early_secret = resumption_keys.early_secret
        else:
            early_secret = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                info=b"\x00",
                salt=b"\x00",
                backend=backend,
            )._extract(b"\x00" * 32)
        
        empty_hash = hashlib.sha256(b"").digest()
        derived_secret = HKDF_Expand_Label(
            key=early_secret,
            algorithm=hashes.SHA256(),
            length=32,
            label="derived",
            context=empty_hash,
            backend=backend,
        )
        handshake_secret = HKDF(
            algorithm=hashes.SHA256(),
            salt=derived_secret,
            info=None,
            backend=backend,
            length=32,
        )._extract(shared_secret)
        client_handshake_traffic_secret = HKDF_Expand_Label(
            context=hello_hash,
            length=32,
            algorithm=hashes.SHA256(),
            label="c hs traffic",
            backend=backend,
            key=handshake_secret,
        )
        server_handshake_traffic_secret = HKDF_Expand_Label(
            context=hello_hash,
            algorithm=hashes.SHA256(),
            length=32,
            label="s hs traffic",
            backend=backend,
            key=handshake_secret,
        )
        client_handshake_key = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            length=16,
            context=b"",
            label="key",
            backend=backend,
            key=client_handshake_traffic_secret,
        )
        server_handshake_key = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            length=16,
            context=b"",
            label="key",
            backend=backend,
            key=server_handshake_traffic_secret,
        )
        client_handshake_iv = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            length=12,
            context=b"",
            label="iv",
            backend=backend,
            key=client_handshake_traffic_secret,
        )
        server_handshake_iv = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            length=12,
            context=b"",
            label="iv",
            backend=backend,
            key=server_handshake_traffic_secret,
        )

        return HandshakeKeys(
            client_key=client_handshake_key,
            client_iv=client_handshake_iv,
            client_handshake_traffic_secret=client_handshake_traffic_secret,
            server_key=server_handshake_key,
            server_iv=server_handshake_iv,
            server_handshake_traffic_secret=server_handshake_traffic_secret,
            handshake_secret=handshake_secret,
        )

    def derive_application_keys(self, handshake_secret: bytes, handshake_hash: bytes):
        empty_hash = hashlib.sha256(b"").digest()
        backend = default_backend()
        derived_secret = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            backend=backend,
            key=handshake_secret,
            label="derived",
            context=empty_hash,
            length=32,
        )
        master_secret = HKDF(
            info=b"\x00",
            salt=derived_secret,
            length=32,
            algorithm=hashes.SHA256(),
            backend=backend,
        )._extract(b"\x00" * 32)
        client_application_traffic_secret = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            backend=backend,
            key=master_secret,
            label="c ap traffic",
            context=handshake_hash,
            length=32,
        )
        server_application_traffic_secret = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            backend=backend,
            key=master_secret,
            label="s ap traffic",
            context=handshake_hash,
            length=32,
        )
        resumption_master_secret = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            backend=backend,
            key=master_secret,
            label="res master",
            context=handshake_hash,
            length=32,
        )
        client_application_key = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            backend=backend,
            key=client_application_traffic_secret,
            label="key",
            context=b"",
            length=16,
        )
        server_application_key = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            backend=backend,
            key=server_application_traffic_secret,
            label="key",
            context=b"",
            length=16,
        )
        client_application_iv = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            backend=backend,
            key=client_application_traffic_secret,
            label="iv",
            context=b"",
            length=12,
        )
        server_application_iv = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            backend=backend,
            key=server_application_traffic_secret,
            label="iv",
            context=b"",
            length=12,
        )

        return ApplicationKeys(
            client_key=client_application_key,
            client_iv=client_application_iv,
            server_key=server_application_key,
            server_iv=server_application_iv,
            resumption_master_secret=resumption_master_secret
        )

    @classmethod
    def generate(klass):
        private_key = X25519PrivateKey.generate()
        return KeyPair(private_key)
