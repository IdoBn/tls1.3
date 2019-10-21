"""
Usage:
s = TLS13Session()
s.connect((host, port))

s.send(b"hello world")
data = s.recv(4096)

s.close()
"""
from socket import socket
from client_hello import ClientHello, ExtensionKeyShare
from server_hello import ServerHello, RecordHeader
from handshake_headers import HandshakeHeader, HANDSHAKE_HEADER_TYPES, HandshakeFinishedHandshakePayload
from change_cipher_suite import ChangeCipherSuite
from wrapper import Wrapper
import hashlib
from crypto import KeyPair, xor_iv, HandshakeKeys
from binascii import hexlify
from io import BytesIO, BufferedReader
from Crypto.Cipher import AES
import struct


class TLS13Session:
    def __init__(self, host, port):
        self.socket = socket()
        self.key_pair = KeyPair.generate()
        self.host = host
        self.port = port
        self.hello_hash_bytes = bytearray()
        self.application_send_counter = 0
        self.application_recv_counter = 0

    def connect(self) -> None:
        self.socket.connect((self.host, self.port))

        # Send ClientHello
        self.send_client_hello()

        # Recv ServerHello
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(4096)))
        sh = self.recv_server_hello(bytes_buffer)
        key_share_ex = [ex for ex in sh.extensions if type(ex) is ExtensionKeyShare][0]
        self.handshake_keys = self.calc_handshake_keys(key_share_ex.public_key_bytes)

        # Recv ServerChangeCipherSuite
        sccs = ChangeCipherSuite.deserialize(bytes_buffer)

        # Server Encrypted Extensions
        plaintext = self.recv_server_encrypted_extensions(bytes_buffer)

        # Calculate Application Keys
        handshake_hash = hashlib.sha256(self.hello_hash_bytes + plaintext).digest()
        self.application_keys = self.key_pair.derive_application_keys(
            self.handshake_keys.handshake_secret, 
            handshake_hash
        )

        # Client change cipher suite
        self.socket.send(sccs.serialize())

        # Client Handshake Finished
        self.send_handshake_finished(self.handshake_keys, handshake_hash)
        
    def send_client_hello(self):
        ch = ClientHello(self.host, self.key_pair.public)
        ch_bytes = ch.serialize()
        self.hello_hash_bytes += ch_bytes[5:]
        self.socket.send(ch_bytes)

    def recv_server_hello(self, bytes_buffer) -> ServerHello:
        original_buffer = bytes_buffer.peek()
        sh = ServerHello.deserialize(bytes_buffer)
        self.hello_hash_bytes += original_buffer[5:sh.record_header.size+5]
        return sh

    def calc_handshake_keys(self, peer_pub_key: bytes) -> HandshakeKeys:
        shared_secret = self.key_pair.exchange(peer_pub_key)
        hello_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        return self.key_pair.derive(shared_secret, hello_hash)

    def recv_server_encrypted_extensions(self, bytes_buffer) -> bytes:
        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += self.socket.recv(wrapper.record_header.size - len(wrapper.payload))

        recdata = wrapper.record_header.serialize()
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        decryptor = AES.new(self.handshake_keys.server_key, AES.MODE_GCM, self.handshake_keys.server_iv)
        decryptor.update(recdata)

        plaintext = decryptor.decrypt(bytes(ciphertext))

        decryptor.verify(authtag)

        plaintext_buffer = BytesIO(plaintext)
        # TODO: change this to walrus operator
        while plaintext_buffer.tell() < len(plaintext) - 1:
            hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
            hh_payload_buffer = plaintext_buffer.read(hh.size)
            hh_payload = HANDSHAKE_HEADER_TYPES[hh.message_type].deserialize(hh_payload_buffer)
        
        return plaintext[:-1]

    def send_handshake_finished(self, handshake_keys: HandshakeKeys, handshake_hash: bytes):
        hh_payload = HandshakeFinishedHandshakePayload.generate(
            handshake_keys.client_handshake_traffic_secret, 
            handshake_hash
        )
        hh_header = HandshakeHeader(
            HandshakeFinishedHandshakePayload.default_htype(), 
            len(hh_payload.verify_data)
        )
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
        self.socket.send(w.serialize())

    def send(self, data: bytes):
        send_data = data + b"\x17"
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16)
        encryptor = AES.new(self.application_keys.client_key, AES.MODE_GCM, xor_iv(self.application_keys.client_iv, self.application_send_counter))
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(send_data)
        tag = encryptor.digest()

        w = Wrapper(record_header=record_header, payload=ciphertext_payload+tag)
        self.socket.send(w.serialize())
        self.application_send_counter += 1

    def _recv(self, bytes_buffer):
        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += self.socket.recv(wrapper.record_header.size - len(wrapper.payload))


        recdata = wrapper.record_header.serialize()
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        decryptor = AES.new(self.application_keys.server_key, AES.MODE_GCM, xor_iv(self.application_keys.server_iv, self.application_recv_counter))
        decryptor.update(recdata)

        plaintext = decryptor.decrypt(bytes(ciphertext))

        decryptor.verify(authtag)
        self.application_recv_counter += 1

        return plaintext

    def recv(self):
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(4096)))
        res = self._recv(bytes_buffer)
        while res[-1] != 0x17:
            res = self._recv(bytes_buffer)

        return res[:-1]

    def close(self):
        self.socket.close()
