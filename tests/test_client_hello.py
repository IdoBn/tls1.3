from unittest import mock
from tls13.client_hello import (
    ClientHelloExtension,
    ExtensionServerName,
    ExtensionSupportedGroups,
    ExtensionSignatureAlgorithms,
    ExtensionKeyShare,
    ExtensionPSKKeyExchangeModes,
    ExtensionSupportedVersions,
    ExtensionEarlyData,
    ExtensionPreSharedKey,
    ClientHello,
)

DOMAIN = b"example.ulfheim.net"
PUB_KEY = bytes.fromhex(
    "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
)

# def test_ExtensionPreSharedKey():
#     session_ticket = b"\xb5\xd9z+\x1b\xa6\x82\x02~\x99[\xc9(\x02\tP\n\x80l\x89U\x85\xcbvI\xdd\xa8)\xcb\x84<\x15g\xb4\xd8EV\x93\xe5\x0f\xd9=\xd5AFwV\xf4'\x96\xd0{7Ak\xc14l\xc4mc\x85\x18f\xde\x1e\x0b/\x9aE\xb5\x17\xf9\xa9\x06n=j\x89r\n\x82}\x00\xa4\xd02\x8c\xf1\x05t\xc6V\x02s\x03\xaa58\xab\xa1\xcf\xb6\xbc#\xba\x00\xda$B\xee\xbe6F\x05F\x16\x02zj\xa8\xfc\xfa\xd5je\x14}\xdf\x81\xac<\x87\x17\x99\xa7i\x91XRT\xf2\x86\rc\xc5\x07M\x88\xc4Z%\n\xfb\x9b\x97\x8e\x02\xe2\x97=\xb9\xb0\x07\x89\x87_4\x83\xac\xf1a\x1a?\xb1>\xa0B+\x9a\xd9\xffs\xb7f\x7fI\x80\xe6(\x9d\xf9\x16\x04\x8f/T\xcfDnP\x08\x85\xb7]9\xd4d\x0f\xeb%\x01\xb6\xd5\x1f\xeb\\y}\xae\xc7\xcb\x9d\x02" 
#     obfuscated_ticket_age = 3837193754 
#     binder_key = b'\x85\xd6t\\\xf5w\xefW0\xd3iB\x9f\r)f\xf0\tY\n\xd1\xa1\x97\x86\xf5\xa8\xd1\x11\xcc\x8e9\x02' 
#     client_hello_hash = b'\x89\x9b\xdc\xcd@\xa0\x9e\x00\x05}\x83\xa1\xb3\xa1\xf9\xce\x86Y\xd5\xf4fz\xed\xaf(\xb0L\x9b|\xf4\xab\xb1'
#     ex = ExtensionPreSharedKey(
#         session_ticket=session_ticket,
#         obfuscated_ticket_age=obfuscated_ticket_age,
#         binder_key=binder_key,
#         client_hello_hash=client_hello_hash
#     )
#     assert ex.serialize()[:2] == bytes.fromhex("0029")
#     # assert ex.serialize()[2:4] == bytes.fromhex("")
#     assert ex.serialize()[4:6] == bytes.fromhex("")
def test_ExtensionPreSharedKey():
    ident = bytes.fromhex("cd1a9be18f3b2c3c9363302e1baffa000ef151287c952ae771d32355b7c7199fd68df04a663e171d18a040b74c4b280f5b3ec6843ab2bf056cbcff073e5d5bb35b98bf566c240b14420d757d7cab9636d07e4c42a1b64b2ac7c07530bb95874de071c2ec4f96bb18a29167bd19863c1e1b2f7a75286da1a7f9a47575374eb0dd78b16af7e24a3ae98bfc84fc7af04abd8771a105ac62e798042a7007c16b4e81d0d50257a2d5dd72954900854588d243bfe84270ba9feb461f5ffe629a5b4d1b8e5125a0de38a3174663ae8c750f26433b79b9939ad3f4377086a666f350c8305425830cd3d75f74f72550a854581a3a")
    obfuscated_ticket_age = 761318983
    binders = bytes.fromhex("82231a941ffa20d14af934050ba6c9e9a7f605640678fa6cc994bc047c1d6337fdc6bcfd6e715bd0a7ae16fe96c02714")
    ex = ExtensionPreSharedKey(
        identity=ident, 
        obfuscated_ticket_age=obfuscated_ticket_age,
        binders=binders,
    )

    assert ex.serialize() == bytes.fromhex("0029012b00f600f0cd1a9be18f3b2c3c9363302e1baffa000ef151287c952ae771d32355b7c7199fd68df04a663e171d18a040b74c4b280f5b3ec6843ab2bf056cbcff073e5d5bb35b98bf566c240b14420d757d7cab9636d07e4c42a1b64b2ac7c07530bb95874de071c2ec4f96bb18a29167bd19863c1e1b2f7a75286da1a7f9a47575374eb0dd78b16af7e24a3ae98bfc84fc7af04abd8771a105ac62e798042a7007c16b4e81d0d50257a2d5dd72954900854588d243bfe84270ba9feb461f5ffe629a5b4d1b8e5125a0de38a3174663ae8c750f26433b79b9939ad3f4377086a666f350c8305425830cd3d75f74f72550a854581a3a2d60ce4700313082231a941ffa20d14af934050ba6c9e9a7f605640678fa6cc994bc047c1d6337fdc6bcfd6e715bd0a7ae16fe96c02714")


def test_ExtensionPreSharedKey_serialize_pre_shared_key_extension():
    ident = bytes.fromhex("cd1a9be18f3b2c3c9363302e1baffa000ef151287c952ae771d32355b7c7199fd68df04a663e171d18a040b74c4b280f5b3ec6843ab2bf056cbcff073e5d5bb35b98bf566c240b14420d757d7cab9636d07e4c42a1b64b2ac7c07530bb95874de071c2ec4f96bb18a29167bd19863c1e1b2f7a75286da1a7f9a47575374eb0dd78b16af7e24a3ae98bfc84fc7af04abd8771a105ac62e798042a7007c16b4e81d0d50257a2d5dd72954900854588d243bfe84270ba9feb461f5ffe629a5b4d1b8e5125a0de38a3174663ae8c750f26433b79b9939ad3f4377086a666f350c8305425830cd3d75f74f72550a854581a3a")
    obfuscated_ticket_age = 761318983
    binders = bytes.fromhex("82231a941ffa20d14af934050ba6c9e9a7f605640678fa6cc994bc047c1d6337fdc6bcfd6e715bd0a7ae16fe96c02714")
    data = ExtensionPreSharedKey.serialize_pre_shared_key_extension(
        identity=ident, 
        obfuscated_ticket_age=obfuscated_ticket_age,
        binders=binders,
    )
    
    assert data == bytes.fromhex("00f600f0cd1a9be18f3b2c3c9363302e1baffa000ef151287c952ae771d32355b7c7199fd68df04a663e171d18a040b74c4b280f5b3ec6843ab2bf056cbcff073e5d5bb35b98bf566c240b14420d757d7cab9636d07e4c42a1b64b2ac7c07530bb95874de071c2ec4f96bb18a29167bd19863c1e1b2f7a75286da1a7f9a47575374eb0dd78b16af7e24a3ae98bfc84fc7af04abd8771a105ac62e798042a7007c16b4e81d0d50257a2d5dd72954900854588d243bfe84270ba9feb461f5ffe629a5b4d1b8e5125a0de38a3174663ae8c750f26433b79b9939ad3f4377086a666f350c8305425830cd3d75f74f72550a854581a3a2d60ce4700313082231a941ffa20d14af934050ba6c9e9a7f605640678fa6cc994bc047c1d6337fdc6bcfd6e715bd0a7ae16fe96c02714")


def test_ExtensionPreSharedKey_serialize_psk_identity():
    ident = bytes.fromhex("cd1a9be18f3b2c3c9363302e1baffa000ef151287c952ae771d32355b7c7199fd68df04a663e171d18a040b74c4b280f5b3ec6843ab2bf056cbcff073e5d5bb35b98bf566c240b14420d757d7cab9636d07e4c42a1b64b2ac7c07530bb95874de071c2ec4f96bb18a29167bd19863c1e1b2f7a75286da1a7f9a47575374eb0dd78b16af7e24a3ae98bfc84fc7af04abd8771a105ac62e798042a7007c16b4e81d0d50257a2d5dd72954900854588d243bfe84270ba9feb461f5ffe629a5b4d1b8e5125a0de38a3174663ae8c750f26433b79b9939ad3f4377086a666f350c8305425830cd3d75f74f72550a854581a3a")
    obfuscated_ticket_age = 761318983
    data = ExtensionPreSharedKey.serialize_psk_identity(
        identity=ident, 
        obfuscated_ticket_age=obfuscated_ticket_age
    )

    assert data == bytes.fromhex("00f0cd1a9be18f3b2c3c9363302e1baffa000ef151287c952ae771d32355b7c7199fd68df04a663e171d18a040b74c4b280f5b3ec6843ab2bf056cbcff073e5d5bb35b98bf566c240b14420d757d7cab9636d07e4c42a1b64b2ac7c07530bb95874de071c2ec4f96bb18a29167bd19863c1e1b2f7a75286da1a7f9a47575374eb0dd78b16af7e24a3ae98bfc84fc7af04abd8771a105ac62e798042a7007c16b4e81d0d50257a2d5dd72954900854588d243bfe84270ba9feb461f5ffe629a5b4d1b8e5125a0de38a3174663ae8c750f26433b79b9939ad3f4377086a666f350c8305425830cd3d75f74f72550a854581a3a2d60ce47")


def test_ExtensionEarlyData():
    da = ExtensionEarlyData()
    assert da.serialize() == b'\x00*\x00\x00'


def test_ExtensionServerName():
    sn = ExtensionServerName(DOMAIN)
    assert sn.serialize() == bytes.fromhex("000000180016000013") + DOMAIN


def test_ExtensionSupportedGroups():
    groups = ExtensionSupportedGroups()
    assert groups.serialize() == bytes.fromhex("000a00080006001d00170018")


def test_ExtensionSignatureAlgorithms():
    signatures = ExtensionSignatureAlgorithms()
    assert signatures.serialize() == bytes.fromhex(
        "000d00140012040308040401050308050501080606010201"
    )


def test_ExtensionKeyShare():
    key_share = ExtensionKeyShare(PUB_KEY)
    assert key_share.serialize() == bytes.fromhex(
        "003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
    )


def test_ExtensionPSKKeyExchangeModes():
    pks_key_modes = ExtensionPSKKeyExchangeModes()
    assert pks_key_modes.serialize() == bytes.fromhex("002d00020101")


def test_ExtensionSupportedVersions():
    supported_versions = ExtensionSupportedVersions()
    assert supported_versions.serialize() == bytes.fromhex("002b0003020304")


COUNTER = 0


def test_ClientHello():
    def mock_random(num):
        global COUNTER
        if COUNTER == 0:
            COUNTER += 1
            return bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
        elif COUNTER == 1:
            return bytes.fromhex(
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            )

    with mock.patch("secrets.token_bytes", mock_random):
        ch = ClientHello(DOMAIN, PUB_KEY)
        assert ch.serialize() == bytes.fromhex(
            "16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304"
        )
