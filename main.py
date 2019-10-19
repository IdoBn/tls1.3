from socket import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from dataclasses import dataclass
from client_hello import ClientHello
from server_hello import ServerHello
from server_change_cipher_suite import ServerChangeCipherSuite
import hashlib
from crypto import KeyPair
from binascii import hexlify
from io import BytesIO, BufferedReader


def main():
    host = b"cloudflare.com"
    port = 443

    key_pair = KeyPair.generate()
    ch = ClientHello(host, key_pair.public)

    hello_hash_bytes = bytearray()
    with socket() as s:
        # syn syn+ack ack
        s.connect((host, port))
        # send client hello
        ch_bytes = ch.serialize()
        s.send(ch_bytes)
        hello_hash_bytes += ch_bytes[5:]
        # receive and deserialize server hello
        orig_bytes_buffer = s.recv(4096)
        bytes_buffer = BufferedReader(BytesIO(orig_bytes_buffer))
        sh = ServerHello.deserialize(bytes_buffer)
        hello_hash_bytes += orig_bytes_buffer[5:sh.record_header.size+5]
    
        # Server change cipher suite
        sccs = ServerChangeCipherSuite.deserialize(bytes_buffer)

        # calculating shared secret
        print(hex(sh.cipher_suite))
        peer_pub_key = sh.extensions[0].public_key_bytes
        shared_secret = key_pair.exchange(peer_pub_key)
        print(shared_secret)

        hello_hash = hashlib.sha256(hello_hash_bytes).digest()
        print([hexlify(i) for i in key_pair.derive(shared_secret, hello_hash)])

if __name__ == "__main__":
    main()
