from socket import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from typing import Tuple
from dataclasses import dataclass
import secrets
import struct
from client_hello import ClientHello

@dataclass
class KeyPair:
    public: bytes
    private: bytes

    @classmethod
    def generate(klass):
        private_key = X25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return KeyPair(public_bytes, private_bytes)


def main():
    host = b"cloudflare.com"
    port = 443

    key_pair = KeyPair.generate()
    public_bytes, _private_bytes = key_pair.public, key_pair.private
    # print(f"public_bytes {len(public_bytes)} {public_bytes}")
    # print(f"private_bytes {len(private_bytes)} {private_bytes}")

    ch = ClientHello(host, public_bytes)
    # print(ch.serialize())

    with socket() as s:
        s.connect((host, port))
        s.send(ch.serialize())
        print(s.recv(4096))


if __name__ == "__main__":
    main()