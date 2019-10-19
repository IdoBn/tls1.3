from socket import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from dataclasses import dataclass
from client_hello import ClientHello
from server_hello import ServerHello
import hashlib
from crypto import KeyPair


def main():
    host = b"cloudflare.com"
    port = 443

    key_pair = KeyPair.generate()
    ch = ClientHello(host, key_pair.public)

    with socket() as s:
        # syn syn+ack ack
        s.connect((host, port))
        # send client hello
        s.send(ch.serialize())
        # receive and deserialize server hello
        sh = ServerHello.deserialize(s.recv(4096))

        # calculating shared secret
        print(hex(sh.cipher_suite))
        peer_pub_key = sh.extensions[0].public_key_bytes
        shared_secret = key_pair.exchange(peer_pub_key)
        print(shared_secret)


if __name__ == "__main__":
    main()
