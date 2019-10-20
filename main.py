from socket import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from dataclasses import dataclass
from client_hello import ClientHello
from server_hello import ServerHello, RecordHeader
from handshake_headers import HandshakeHeader, HANDSHAKE_HEADER_TYPES, HandshakeFinishedHandshakePayload
from change_cipher_suite import ChangeCipherSuite
from wrapper import Wrapper
import hashlib
from crypto import KeyPair
from binascii import hexlify
from io import BytesIO, BufferedReader
from Crypto.Cipher import AES

def xor_last_8_bytes(iv):
    return iv[:4] + bytes([b ^ 1 for b in iv[4:]])

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
        handshake_keys = key_pair.derive(shared_secret, hello_hash)
    
        # Server change cipher suite
        sccs = ChangeCipherSuite.deserialize(bytes_buffer)
        print(sccs)

        # Server Encrypted Extensions
        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += s.recv(wrapper.record_header.size - len(wrapper.payload))

        print(wrapper.record_header, len(wrapper.payload))

        recdata = wrapper.record_header.serialize()
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        decryptor = AES.new(handshake_keys.server_key, AES.MODE_GCM, handshake_keys.server_iv)
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

        # Calculate Application Keys
        handshake_hash = hashlib.sha256(hello_hash_bytes + plaintext[:-1]).digest()
        application_keys = key_pair.derive_application_keys(handshake_keys.handshake_secret, handshake_hash)
        print(application_keys)

        # Client change cipher suite
        s.send(sccs.serialize())

        # Client Handshake Finished
        hh_payload = HandshakeFinishedHandshakePayload.generate(handshake_keys.client_handshake_traffic_secret, handshake_hash)
        hh_header = HandshakeHeader(HandshakeFinishedHandshakePayload.default_htype(), len(hh_payload.verify_data))
        plaintext_payload = b"".join([
            hh_header.serialize(),
            hh_payload.verify_data,
            b"\x16"
        ])

        record_header = RecordHeader(rtype=0x17, size=len(plaintext_payload) + 16)

        encryptor = AES.new(handshake_keys.client_key, AES.MODE_GCM, handshake_keys.client_iv)
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(plaintext_payload)
        tag = encryptor.digest()

        w = Wrapper(record_header=record_header, payload=ciphertext_payload+tag)
        s.send(w.serialize())

        # Send HTTP Get Request!
        http_data = b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n"+b"\x17"
        record_header = RecordHeader(rtype=0x17, size=len(http_data) + 16)
        encryptor = AES.new(application_keys.client_key, AES.MODE_GCM, application_keys.client_iv)
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(http_data)
        tag = encryptor.digest()

        # Reading Session Tickets!
        w = Wrapper(record_header=record_header, payload=ciphertext_payload+tag)
        s.send(w.serialize())

        orig_bytes_buffer = s.recv(4096)
        bytes_buffer = BufferedReader(BytesIO(orig_bytes_buffer))
        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += s.recv(wrapper.record_header.size - len(wrapper.payload))

        print(len(wrapper.payload), wrapper.record_header.size)

        recdata = wrapper.record_header.serialize()
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        decryptor = AES.new(application_keys.server_key, AES.MODE_GCM, application_keys.server_iv)
        decryptor.update(recdata)

        plaintext = decryptor.decrypt(bytes(ciphertext))
        print(plaintext, len(plaintext))

        decryptor.verify(authtag)

        # HTTP Response
        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += s.recv(wrapper.record_header.size - len(wrapper.payload))

        print(wrapper.record_header)
        print(len(wrapper.payload), wrapper.record_header.size)

        recdata = wrapper.record_header.serialize()
        print(recdata)
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        old_iv = application_keys.server_iv
        new_iv = bytearray(application_keys.server_iv)
        # TODO: make this way!!! more generic!!!
        new_iv[-1] ^= 1
        print(f"old_iv={old_iv}, new_iv={new_iv}")
        decryptor = AES.new(application_keys.server_key, AES.MODE_GCM, new_iv)
        decryptor.update(recdata)

        plaintext = decryptor.decrypt(bytes(ciphertext))
        print(plaintext)

        decryptor.verify(authtag)


        

    print("done!")

        

if __name__ == "__main__":
    main()
