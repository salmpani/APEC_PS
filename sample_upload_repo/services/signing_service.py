from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

DATA_RETENTION_YEARS = 12


def create_signing_keys():
    customer_archive_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transaction_signing_key = ec.generate_private_key(ec.SECP256R1())
    return customer_archive_key, transaction_signing_key


def legacy_digest(payload: bytes):
    digest = hashes.Hash(hashes.SHA1())
    digest.update(payload)
    return digest.finalize()
