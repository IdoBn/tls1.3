from socket import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from dataclasses import dataclass
from client_hello import ClientHello
from server_hello import ServerHello
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
        authtag = wrapper.payload[-16:]#bytes.fromhex("e08b0e455a350ae54d76349aa68c71ae")

        ciphertext = wrapper.payload[:-16]#bytes.fromhex("da1ec2d7bda8ebf73edd5010fba8089fd426b0ea1ea4d88d074ffea8a9873af5f502261e34b1563343e9beb6132e7e836d65db6dcf00bc401935ae369c440d67af719ec03b984c4521b905d58ba2197c45c4f773bd9dd121b4d2d4e6adfffa27c2a81a99a8efe856c35ee08b71b3e441bbecaa65fe720815cab58db3efa8d1e5b71c58e8d1fdb6b21bfc66a9865f852c1b4b640e94bd908469e7151f9bbca3ce53224a27062ceb240a105bd3132dc18544477794c373bc0fb5a267885c857d4ccb4d31742b7a29624029fd05940de3f9f9b6e0a9a237672bc624ba2893a21709833c5276d413631bdde6ae7008c697a8ef428a79dbf6e8bbeb47c4e408ef656d9dc19b8b5d49bc091e2177357594c8acd41c101c7750cb11b5be6a194b8f877088c9828e3507dada17bb14bb2c738903c7aab40c545c46aa53823b120181a16ce92876288c4acd815b233d96bb572b162ec1b9d712f2c3966caac9cf174f3aedfec4d19ff9a87f8e21e8e1a9789b490ba05f1debd21732fb2e15a017c475c4fd00be042186dc29e68bb7ece192438f3b0c5ef8e4a53583a01943cf84bba5842173a6b3a7289566687c3018f764ab18103169919328713c3bd463d3398a1feb8e68e44cfe482f72847f46c80e6cc7f6ccf179f482c888594e76276653b48398a26c7c9e420cb6c1d3bc7646f33bb832bfba98489cadfbd55dd8b2c57687a47acba4ab390152d8fbb3f20327d824b284d288fb0152e49fc44678aed4d3f085b7c55de77bd45af812fc37944ad2454f99fbb34a583bf16b67659e6f216d34b1d79b1b4decc098a44207e1c5feeb6ce30acc2cf7e2b134490b442744772d184e59038aa517a97154181e4dfd94fe72a5a4ca2e7e22bce733d03e7d9319710befbc30d7826b728519ba74690e4f906587a0382895b90d82ed3e357faf8e59aca85fd2063ab592d83d245a919ea53c501b9accd2a1ed951f43c049ab9d25c7f1b70ae4f942edb1f311f7417833062245b429d4f013ae9019ff52044c97c73b8882cf03955c739f874a029637c0f0607100e3070f408d082aa7a2abf13e73bd1e252c228aba7a9c1f075bc439571b35932f5c912cb0b38da1c95e64fcf9bfec0b9b0dd8f042fdf05e5058299e96e4185074919d90b7b3b0a97e2242ca08cd99c9ecb12fc49adb2b257240cc387802f00e0e49952663ea278408709bce5b363c036093d7a05d440c9e7a7abb3d71ebb4d10bfc7781bcd66f79322c18262dfc2dccf3e5f1ea98bea3caae8a83706312764423a692ae0c1e2e23b016865ffb125b223857547ac7e2468433b5269843abbabbe9f6f438d7e387e3617a219f62540e7343e1bbf49355fb5a1938048439cba5cee819199b2b5c39fd351aa274536aadb682b578943f0ccf48e4ec7ddc938e2fd01acfaa1e7217f7b389285c0dfd31a1545ed3a85fac8eb9dab6ee826af90f9e1ee5d555dd1c05aec077f7c803cbc2f1cf98393f0f37838ffea372ff708886b05934e1a64512de144608864a88a5c3a173fdcfdf5725da916ed507e4caec8787befb91e3ec9b222fa09f374bd96881ac2ddd1f885d42ea584c")

        decryptor = AES.new(server_handshake_key, AES.MODE_GCM, server_handshake_iv)
        decryptor.update(recdata)

        plaintext = decryptor.decrypt(bytes(ciphertext))
        print(plaintext)

        print(decryptor.verify(authtag))
        

        

if __name__ == "__main__":
    main()
