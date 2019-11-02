from io import BytesIO, BufferedReader
from tls13.change_cipher_suite import ChangeCipherSuite

CHANGE_CIPHER_SUITE_PACKET = bytes.fromhex("140303000101")


def test_ChangeCipherSuite_deserialize():
    ccs = ChangeCipherSuite.deserialize(
        BufferedReader(BytesIO(CHANGE_CIPHER_SUITE_PACKET))
    )
    assert ccs.record_header.rtype == 0x14
    assert ccs.payload == b"\x01"


def test_ChangeCipherSuite_serialize():
    ccs = ChangeCipherSuite.deserialize(
        BufferedReader(BytesIO(CHANGE_CIPHER_SUITE_PACKET))
    )
    assert ccs.serialize() == CHANGE_CIPHER_SUITE_PACKET
