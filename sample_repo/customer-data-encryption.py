from cryptography.hazmat.primitives.asymmetric import rsa, ec

DATA_RETENTION_YEARS = 15

def generate_legacy_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ecc_key = ec.generate_private_key(ec.SECP256R1())
    return rsa_key, ecc_key