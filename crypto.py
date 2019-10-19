from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from dataclasses import dataclass
import hashlib
import struct

def HKDF_Expand_Label(key, label, context, length, backend, algorithm):
    tmp_label = b"tls13 " + label.encode()
    hkdf_label = struct.pack(">h", length) + struct.pack("b", len(tmp_label)) + tmp_label + struct.pack("b", len(context)) + context
    return HKDFExpand(
        algorithm=algorithm, 
        length=length, 
        info=hkdf_label, 
        backend=backend
    ).derive(key)

@dataclass
class KeyPair:
    private_key: X25519PrivateKey

    @property
    def public(self) -> bytes:
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return public_bytes

    @property
    def private(self) -> bytes:
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_bytes

    def exchange(self, peer_pub_key_bytes: bytes) -> bytes: 
        peer_pub_key = X25519PublicKey.from_public_bytes(peer_pub_key_bytes)
        shared_key = self.private_key.exchange(peer_pub_key)
        return shared_key

    def derive(self, shared_secret: bytes, hello_hash: bytes):
        backend = default_backend()
        early_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"\x00",
            salt=b"\x00",
            backend=backend
        )._extract(b"\x00" * 32)
        empty_hash = hashlib.sha256(b"").digest()
        derived_secret = HKDF_Expand_Label(
            key=early_secret,
            algorithm=hashes.SHA256(), 
            length=32,
            label="derived",
            context=empty_hash, 
            backend=backend
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
            key=handshake_secret
        )
        server_handshake_traffic_secret = HKDF_Expand_Label(
            context=hello_hash,
            algorithm=hashes.SHA256(),
            length=32,
            label="s hs traffic",
            backend=backend,
            key=handshake_secret
        )
        client_handshake_key = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            length=16,
            context=b"",
            label="key",
            backend=backend,
            key=client_handshake_traffic_secret
        )
        server_handshake_key = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            length=16,
            context=b"",
            label="key",
            backend=backend,
            key=server_handshake_traffic_secret
        )
        client_handshake_iv = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            length=12,
            context=b"",
            label="iv",
            backend=backend,
            key=client_handshake_traffic_secret
        )
        server_handshake_iv = HKDF_Expand_Label(
            algorithm=hashes.SHA256(),
            length=12,
            context=b"",
            label="iv",
            backend=backend,
            key=server_handshake_traffic_secret
        )

        return client_handshake_key, client_handshake_iv, server_handshake_key, server_handshake_iv
        

    @classmethod
    def generate(klass):
        private_key = X25519PrivateKey.generate()
        return KeyPair(private_key)