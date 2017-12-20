import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import time
from cryptography.hazmat.primitives import hashes, hmac, serialization


# Generate a 4096 bit private key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend())
# to get the public key
public_key = private_key.public_key()

print public_key

print "-------------------------------------------------------"

# Generate a 4096 bit private key 2

private_key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend())
# to get the public key
public_key2 = private_key2.public_key()





from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ciphertext = public_key.encrypt(
    public_key2,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA256(),
        label=None))
print base64.b64encode(ciphertext)














