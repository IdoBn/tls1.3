from unittest import mock
from client_hello import ClientHelloExtension, ExtensionServerName, ExtensionSupportedGroups, ExtensionSignatureAlgorithms, ExtensionKeyShare, ExtensionPSKKeyExchangeModes, ExtensionSupportedVersions, ClientHello

DOMAIN = b"example.ulfheim.net"
PUB_KEY = bytes.fromhex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254")

def test_ExtensionServerName():
    sn = ExtensionServerName(DOMAIN)
    assert sn.serialize() == bytes.fromhex("000000180016000013") + DOMAIN


def test_ExtensionSupportedGroups():
    groups = ExtensionSupportedGroups()
    assert groups.serialize() == bytes.fromhex("000a00080006001d00170018")


def test_ExtensionSignatureAlgorithms():
    signatures = ExtensionSignatureAlgorithms()
    assert signatures.serialize() == bytes.fromhex(
        "000d00140012040308040401050308050501080606010201")


def test_ExtensionKeyShare():
    key_share = ExtensionKeyShare(PUB_KEY)
    assert key_share.serialize() == bytes.fromhex("003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254")


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
            return bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        elif COUNTER == 1:
            return bytes.fromhex("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        

    with mock.patch("secrets.token_bytes", mock_random):
        ch = ClientHello(DOMAIN, PUB_KEY)
        assert ch.serialize() == bytes.fromhex("16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304")