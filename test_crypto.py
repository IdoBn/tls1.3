from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from unittest import mock
from crypto import KeyPair

def get_mocked_keypair() -> KeyPair:
    def mock_generate_private_key():
        return X25519PrivateKey.from_private_bytes(bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
        
    with mock.patch("cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate", mock_generate_private_key):
        return KeyPair.generate()

def test_KeyExchange():
    key_pair = get_mocked_keypair()
    peer_pub_key_bytes = bytes.fromhex("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")
    assert key_pair.exchange(peer_pub_key_bytes) == bytes.fromhex("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624")

def test_KeyPair_derive():
    key_pair = get_mocked_keypair()
    shared_secret = bytes.fromhex("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624")
    hello_hash = bytes.fromhex("da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5")

    keys = key_pair.derive(shared_secret, hello_hash)
    assert keys.client_key == bytes.fromhex("7154f314e6be7dc008df2c832baa1d39")
    assert keys.client_iv == bytes.fromhex("71abc2cae4c699d47c600268")
    assert keys.client_handshake_traffic_secret == bytes.fromhex("ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea")
    assert keys.server_key == bytes.fromhex("844780a7acad9f980fa25c114e43402a")
    assert keys.server_iv == bytes.fromhex("4c042ddc120a38d1417fc815")
    assert keys.server_handshake_traffic_secret == bytes.fromhex("a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814")
    assert keys.handshake_secret == bytes.fromhex("fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a")

def test_KeyPair_derive_application_keys():
    handshake_secret = bytes.fromhex("fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a")
    handshake_hash = bytes.fromhex("22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b")

    key_pair = get_mocked_keypair()
    keys = key_pair.derive_application_keys(handshake_secret, handshake_hash)
    assert keys.client_key == bytes.fromhex("49134b95328f279f0183860589ac6707")
    assert keys.client_iv == bytes.fromhex("bc4dd5f7b98acff85466261d")
    assert keys.server_key == bytes.fromhex("0b6d22c8ff68097ea871c672073773bf")
    assert keys.server_iv == bytes.fromhex("1b13dd9f8d8f17091d34b349")