from socket import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from dataclasses import dataclass
from client_hello import ClientHello
from server_hello import ServerHello
from handshake_headers import HandshakeHeader, HANDSHAKE_HEADER_TYPES
from server_change_cipher_suite import ServerChangeCipherSuite
from wrapper import Wrapper
import hashlib
from crypto import KeyPair
from binascii import hexlify
from io import BytesIO, BufferedReader
from Crypto.Cipher import AES


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

        # calculating shared secret
        print(hex(sh.cipher_suite))
        peer_pub_key = sh.extensions[0].public_key_bytes
        shared_secret = key_pair.exchange(peer_pub_key)
        print(shared_secret)
        hello_hash = hashlib.sha256(hello_hash_bytes).digest()
        client_handshake_key, client_handshake_iv, server_handshake_key, server_handshake_iv = key_pair.derive(shared_secret, hello_hash)
    
        # Server change cipher suite
        sccs = ServerChangeCipherSuite.deserialize(bytes_buffer)
        print(sccs)

        # wrapper
        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += s.recv(wrapper.record_header.size - len(wrapper.payload))

        print(wrapper.record_header, len(wrapper.payload))

        recdata = wrapper.record_header.serialize()
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        decryptor = AES.new(server_handshake_key, AES.MODE_GCM, server_handshake_iv)
        decryptor.update(recdata)

        plaintext = decryptor.decrypt(bytes(ciphertext))
        print(plaintext)

        decryptor.verify(authtag)

        plaintext_buffer = BytesIO(plaintext)
        # TODO: change this to walrus operator
        while plaintext_buffer.tell() < len(plaintext) - 1:
            print(f"{plaintext_buffer.tell()} < {len(plaintext) - 1} ")
            hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
            print(hh)
            hh_payload_buffer = plaintext_buffer.read(hh.size)
            hh_payload = HANDSHAKE_HEADER_TYPES[hh.message_type].deserialize(hh_payload_buffer)
            print(hh_payload)

        

        

if __name__ == "__main__":
    main()
