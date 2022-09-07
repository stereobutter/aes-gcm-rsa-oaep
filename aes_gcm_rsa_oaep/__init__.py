from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from typing import Optional
from .types import RSAPrivateKey, RSAPublicKey


def encrypt(plaintext: bytes, public_key: RSAPublicKey, label: Optional[bytes] = None):
    session_key = AESGCM.generate_key(bit_length=256)
    rsa_cipher_text = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=label))
    rsa_ciphertext_length = len(rsa_cipher_text).to_bytes(2, 'big', signed=False)
    aesgcm = AESGCM(session_key)
    cipher_text = aesgcm.encrypt(nonce=bytearray(12), data=plaintext, associated_data=None)
    return rsa_ciphertext_length + rsa_cipher_text + cipher_text


def decrypt(ciphertext: bytes, private_key: RSAPrivateKey, label:Optional[bytes] = None):
    rsa_ciphertext_lenth = int.from_bytes(ciphertext[0:2], 'big')
    rsa_ciphertext = ciphertext[2: rsa_ciphertext_lenth + 2]
    aes_ciphertext = ciphertext[rsa_ciphertext_lenth + 2:]
    
    session_key = private_key.decrypt(
        rsa_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=label
        )
    )
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(bytearray(12), aes_ciphertext, None)
    return plaintext
