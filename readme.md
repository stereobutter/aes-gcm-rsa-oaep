# AES-GCM + RSA OAEP encryption (as used by kubeseal)

## Installation

```
pip install aes-gcm-rsa-oaep
```

> :notes: This module depends on the `cryptography`(https://pypi.org/project/cryptography/) module. See [here](https://cryptography.io/en/latest/installation/#building-cryptography-on-linux) for instructions on how to install or build `cryptography` your platform. 

## Usage
```python
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from aes_gcm_rsa_oaep import encrypt, decrypt

private_key = generate_private_key(public_exponent=65537, key_size=4096)
public_key = private_key.public_key()

plaintext = b'hello world'
label='my-namespace/my-secret'

ciphertext = encrypt(plaintext, public_key, label)

assert plaintext == decrypt(ciphertext, private_key, label)
```

## Encryption Algorithm
The implementation follows and is compatible with https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md

Encrypting a plaintext works as follows:
* a 256 bit random session key is generated
* AES-GCM is used to encrypt the plaintext using the session key
* the session key is encrypted using a provideded RSA public key
* the resulting payload is the concatenated RSA ciphertext length (2 bytes), the RSA encrypted session key and the AES encrypted plaintext 

Decrypting a ciphertext works by following the procedure in reverse
* extraction of the RSA ciphertext length, RSA encrypted session key and the AES encrypted plaintext
* the session key is decrypted using the RSA private key
* the session key is used to decrypt the AES encrypted plaintext 