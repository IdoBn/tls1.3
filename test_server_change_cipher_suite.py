from io import BytesIO, BufferedReader
from server_change_cipher_suite import ServerChangeCipherSuite

def test_ServerChangeCipherSuite_deserialize():
    sccs = ServerChangeCipherSuite.deserialize(BufferedReader(BytesIO(bytes.fromhex("140303000101"))))
    assert sccs.record_header.rtype == 0x14
    assert sccs.payload == b"\x01"