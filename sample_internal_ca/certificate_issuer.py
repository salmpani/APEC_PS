from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

RETENTION_YEARS = 18


def create_demo_ca_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def legacy_certificate_digest(payload: bytes):
    digest = hashes.Hash(hashes.SHA1())
    digest.update(payload)
    return digest.finalize()
