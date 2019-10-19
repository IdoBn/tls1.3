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

    client_handshake_key, client_handshake_iv, server_handshake_key, server_handshake_iv = key_pair.derive(shared_secret, hello_hash)
    assert client_handshake_key == bytes.fromhex("7154f314e6be7dc008df2c832baa1d39")
    assert client_handshake_iv == bytes.fromhex("71abc2cae4c699d47c600268")
    assert server_handshake_key == bytes.fromhex("844780a7acad9f980fa25c114e43402a")
    assert server_handshake_iv == bytes.fromhex("4c042ddc120a38d1417fc815")
