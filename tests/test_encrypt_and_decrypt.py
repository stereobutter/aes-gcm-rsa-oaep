import pytest
from hypothesis import given, strategies as st
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from aes_gcm_rsa_oaep import encrypt, decrypt


@pytest.fixture(scope='session')
def rsa_keypair():
    key = generate_private_key(public_exponent=65537, key_size=4096)
    return key.public_key(), key


@given(plaintext=st.binary(), label=st.binary())
def test_roundtripping(plaintext, label, rsa_keypair):
    public_key, private_key = rsa_keypair
    assert plaintext == decrypt(encrypt(plaintext, public_key, label), private_key, label)
