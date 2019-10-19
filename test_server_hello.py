from server_hello import RecordHeader, HandshakeHeader, ServerHello
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from unittest import mock
from io import BufferedReader, BytesIO


def test_RecordHeader():
    rh = RecordHeader.deserialize(bytes.fromhex("160303007a"))
    assert rh.size == 0x7a
    assert rh.rtype == 0x16
    assert rh.legacy_proto_version == 0x0303
    assert rh.serialize() == bytes.fromhex("160303007a")

def test_HandshakeHeader():
    hh = HandshakeHeader.deserialize(bytes.fromhex("02000076"))
    assert hh.size == 0x76
    assert hh.message_type == 0x02

def test_ServerHello():
    server_hello_packet = bytes.fromhex("160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304")
    sh = ServerHello.deserialize(BufferedReader(BytesIO(server_hello_packet)))
    assert sh.record_header.rtype == 0x16
    assert sh.record_header.legacy_proto_version == 0x0303
    assert sh.record_header.size == 0x007a

    assert sh.handshake_header.message_type == 0x02
    assert sh.handshake_header.size == 0x76

    assert sh.server_version == 0x0303
    assert sh.server_random == bytes.fromhex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
    assert sh.session_id == bytes.fromhex("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    assert sh.cipher_suite == 0x1301

    assert len(sh.extensions) == 2
    assert sh.extensions[0].public_key_bytes == bytes.fromhex("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")
    assert sh.extensions[1].data == 0x0304