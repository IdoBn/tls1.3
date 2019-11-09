"""
Usage:
s = TLS13Session()
s.connect((host, port))

s.send(b"hello world")
data = s.recv(4096)

s.close()
"""
from socket import socket, timeout
from tls13.client_hello import ClientHello, ExtensionKeyShare, ExtensionPreSharedKey, ExtensionEarlyData, ExtensionServerName
from tls13.server_hello import ServerHello, RecordHeader
from tls13.handshake_headers import (
    HandshakeHeader,
    HANDSHAKE_HEADER_TYPES,
    HandshakeFinishedHandshakePayload,
    NewSessionTicketHandshakePayload,
)
from tls13.change_cipher_suite import ChangeCipherSuite
from tls13.wrapper import Wrapper
import hashlib
from tls13.crypto import KeyPair, xor_iv, HandshakeKeys
from binascii import hexlify
from io import BytesIO, BufferedReader
from Crypto.Cipher import AES
import struct
from tls13.crypto import HKDF_Expand_Label
import hmac


class TLS13Session:
    def __init__(self, host, port, timeout=2.0):
        self.socket = socket()
        self.socket.settimeout(timeout)
        self.key_pair = KeyPair.generate()
        self.host = host
        self.port = port
        self.hello_hash_bytes = bytearray()
        self.handshake_send_counter = 0
        self.handshake_recv_counter = 0
        self.application_send_counter = 0
        self.application_recv_counter = 0
        self.session_tickets = []

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

        self.hello_hash_bytes += plaintext

        # Calculate Application Keys
        handshake_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        self.application_keys = self.key_pair.derive_application_keys(
            self.handshake_keys.handshake_secret, handshake_hash
        )

        # Client change cipher suite
        self.socket.send(sccs.serialize())

        # Client Handshake Finished
        self.send_handshake_finished(self.handshake_keys, handshake_hash)

    def resume(self) -> None:
        if self.application_keys is None:
            raise Exception("Can't Resume TLS1.3 Session")

        session_ticket = self.session_tickets[0]
        
        print("keys", self.application_keys)
        resumption_master_secret = self.application_keys.resumption_master_secret(hashlib.sha256(self.hello_hash_bytes).digest())
        print("resumption_master_secret", hexlify(resumption_master_secret))
        self.resumption_keys = self.key_pair.derive_early_keys(session_ticket.psk(resumption_master_secret), b"")
        print("binder_key", hexlify(self.resumption_keys.binder_key))

        finished_key = HKDF_Expand_Label(
            key=self.resumption_keys.binder_key,
            label="finished",
            context=b"",
            length=32,
        )
        verify_data = hmac.new(
            finished_key, msg=b"", digestmod=hashlib.sha256
        ).digest()
        psk_binders = verify_data
        print("finished_key", hexlify(finished_key))

        offset = len(ExtensionPreSharedKey.serialize_binders(psk_binders))

        pre_share_key_ext = ExtensionPreSharedKey(
            identity=session_ticket.session_ticket, 
            obfuscated_ticket_age=session_ticket.obfuscated_ticket_age, 
            binders=psk_binders)

        ch = ClientHello(self.host, self.key_pair.public)
        # ch.extensions = [ex for ex in ch.extensions if type(ex) is not ExtensionServerName]
        ch.add_extension(ExtensionEarlyData())
        ch.add_extension(pre_share_key_ext)

        ch_bytes = ch.serialize()
        my_hello_hash = hashlib.sha256(ch_bytes[5:-offset]).digest()
        print("my_hash", hexlify(my_hello_hash))
        print("my_hash_offset", hexlify(ch_bytes[5:-offset]))


        finished_key = HKDF_Expand_Label(
            key=self.resumption_keys.binder_key,
            label="finished",
            context=b"",
            length=32,
        )
        verify_data = hmac.new(
            finished_key, msg=my_hello_hash, digestmod=hashlib.sha256
        ).digest()
        print("finished_key", hexlify(finished_key))
        psk_binders = verify_data
        
        print("psk_binders", hexlify(psk_binders))

        
        final_hash = hashlib.sha256(ch_bytes[5:]).digest()
        print("final_hash", hexlify(final_hash))
        self.resumption_keys = self.key_pair.derive_early_keys(session_ticket.psk(resumption_master_secret), final_hash)
        pre_share_key_ext = ExtensionPreSharedKey(
            identity=session_ticket.session_ticket, 
            obfuscated_ticket_age=session_ticket.obfuscated_ticket_age, 
            binders=psk_binders)

        ch.extensions = [ex for ex in ch.extensions if type(ex) is not ExtensionPreSharedKey]
        # ch.extensions = [ex for ex in ch.extensions if type(ex) is not ExtensionServerName]
        ch.add_extension(pre_share_key_ext)

        ch_bytes_final = ch.serialize()
        # print(len(ch_bytes_final), ch_bytes_final)

        final_hash = hashlib.sha256(ch_bytes_final[5:]).digest()
        print("final_hash", hexlify(final_hash))
        self.resumption_keys = self.key_pair.derive_early_keys(session_ticket.psk(resumption_master_secret), final_hash)

        self.socket = socket()
        self.socket.connect((self.host, self.port))
    

        data = f"GET /testing HTTP/1.1\r\nHost: {self.host.decode()}\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".encode()
        send_data = data + b"\x17"
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16)
        print("client_early_traffic_secret", hexlify(self.resumption_keys.client_early_traffic_secret))
        print("client_early_key", hexlify(self.resumption_keys.client_early_key))
        print("client_early_iv", hexlify(self.resumption_keys.client_early_iv))
        encryptor = AES.new(
            self.resumption_keys.client_early_key,
            AES.MODE_GCM,
            xor_iv(self.resumption_keys.client_early_iv, 0),
        )
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(send_data)
        tag = encryptor.digest()

        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        self.socket.send(ch_bytes_final + bytes.fromhex("140303000101") + w.serialize())
        


        print("res", self.socket.recv(4096))
        print("res", self.socket.recv(4096))



    def send_client_hello(self):
        ch = ClientHello(self.host, self.key_pair.public)
        ch_bytes = ch.serialize()
        self.hello_hash_bytes += ch_bytes[5:]
        self.socket.send(ch_bytes)

    def recv_server_hello(self, bytes_buffer) -> ServerHello:
        original_buffer = bytes_buffer.peek()
        sh = ServerHello.deserialize(bytes_buffer)
        self.hello_hash_bytes += original_buffer[5 : sh.record_header.size + 5]
        return sh

    def calc_handshake_keys(self, peer_pub_key: bytes) -> HandshakeKeys:
        shared_secret = self.key_pair.exchange(peer_pub_key)
        print("shared secret", shared_secret)
        hello_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        return self.key_pair.derive(shared_secret, hello_hash)

    def recv_server_encrypted_extensions(self, bytes_buffer) -> bytes:
        def parse_wrapper(bytes_buffer):
            wrapper = Wrapper.deserialize(bytes_buffer)
            while wrapper.record_header.size > len(wrapper.payload):
                wrapper.payload += self.socket.recv(
                    wrapper.record_header.size - len(wrapper.payload)
                )

            recdata = wrapper.record_header.serialize()
            authtag = wrapper.auth_tag

            ciphertext = wrapper.encrypted_data

            decryptor = AES.new(
                self.handshake_keys.server_key,
                AES.MODE_GCM,
                xor_iv(self.handshake_keys.server_iv, self.handshake_recv_counter),
            )
            decryptor.update(recdata)

            plaintext = decryptor.decrypt(bytes(ciphertext))
            self.handshake_recv_counter += 1

            decryptor.verify(authtag)
            return plaintext[:-1]

        plaintext = bytearray()
        plaintext += parse_wrapper(bytes_buffer)
        plaintext_buffer = BufferedReader(BytesIO(plaintext))
        # TODO: change this to walrus operator
        while True:
            if len(plaintext_buffer.peek()) < 4:
                res = parse_wrapper(bytes_buffer)
                plaintext += res
                plaintext_buffer = BufferedReader(
                    BytesIO(plaintext_buffer.peek() + res)
                )

            hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
        
            hh_payload_buffer = plaintext_buffer.read(hh.size)
            while len(hh_payload_buffer) < hh.size:
                res = parse_wrapper(bytes_buffer)
                plaintext += res
                plaintext_buffer = BufferedReader(
                    BytesIO(plaintext_buffer.peek() + res)
                )

                prev_len = len(hh_payload_buffer)
                hh_payload_buffer = hh_payload_buffer + plaintext_buffer.read(
                    hh.size - prev_len
                )

            
            hh_payload = HANDSHAKE_HEADER_TYPES[hh.message_type].deserialize(
                hh_payload_buffer
            )
    
            if type(hh_payload) is HandshakeFinishedHandshakePayload:
                break

        return plaintext

    def send_handshake_finished(
        self, handshake_keys: HandshakeKeys, handshake_hash: bytes
    ):
        hh_payload = HandshakeFinishedHandshakePayload.generate(
            handshake_keys.client_handshake_traffic_secret, handshake_hash
        )
        hh_header = HandshakeHeader(
            HandshakeFinishedHandshakePayload.default_htype(),
            len(hh_payload.verify_data),
        )
        plaintext_payload = b"".join(
            [hh_header.serialize(), hh_payload.verify_data, b"\x16"]
        )

        self.hello_hash_bytes += plaintext_payload[:-1]

        record_header = RecordHeader(rtype=0x17, size=len(plaintext_payload) + 16)

        encryptor = AES.new(
            handshake_keys.client_key, AES.MODE_GCM, handshake_keys.client_iv
        )
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(plaintext_payload)
        tag = encryptor.digest()

        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        self.socket.send(w.serialize())

    def send(self, data: bytes):
        send_data = data + b"\x17"
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16)
        encryptor = AES.new(
            self.application_keys.client_key,
            AES.MODE_GCM,
            xor_iv(self.application_keys.client_iv, self.application_send_counter),
        )
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(send_data)
        tag = encryptor.digest()

        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        self.socket.send(w.serialize())
        self.application_send_counter += 1

    def __recv(self, bytes_buffer):

        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += self.socket.recv(
                wrapper.record_header.size - len(wrapper.payload)
            )

        recdata = wrapper.record_header.serialize()
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        decryptor = AES.new(
            self.application_keys.server_key,
            AES.MODE_GCM,
            xor_iv(self.application_keys.server_iv, self.application_recv_counter),
        )
        decryptor.update(recdata)

        plaintext = decryptor.decrypt(bytes(ciphertext))

        decryptor.verify(authtag)
        self.application_recv_counter += 1

        return plaintext

    def _recv(self):
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(4096)))

        if len(bytes_buffer.peek()) < 4:
            bytes_buffer = BufferedReader(
                BytesIO(bytes_buffer.read() + self.socket.recv(4096))
            )
        res = self.__recv(bytes_buffer)
        # while res[-1] != 0x17:
        # count =1
        while True:
            if res[-1] == 0x17:
                yield res[:-1]
            if res[-1] == 0x16:
                plaintext_buffer = BufferedReader(BytesIO(res[:-1]))
                while plaintext_buffer.peek():
                    hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
                    hh_payload_buffer = plaintext_buffer.read(hh.size)
                    hh_payload = HANDSHAKE_HEADER_TYPES[hh.message_type].deserialize(
                        hh_payload_buffer
                    )
                    if type(hh_payload) is NewSessionTicketHandshakePayload:
                        self.session_tickets.append(hh_payload)

            if len(bytes_buffer.peek()) < 4:
                bytes_buffer = BufferedReader(
                    BytesIO(bytes_buffer.read() + self.socket.recv(4096))
                )

                if len(bytes_buffer.peek()) < 4:
                    break

            res = self.__recv(bytes_buffer)

    def recv(self):
        res = bytearray()
        try:
            for data in self._recv():
                res += data
        except timeout:
            pass

        return res

    def close(self):
        self.socket.close()
