"""Fixture: RSA encryption through `cryptography` padding objects, AEAD key generation, bcrypt defaults."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import bcrypt


def wrap_session_key(partner_public_key, session_key):
    return partner_public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def legacy_unwrap(private_key, blob):
    return private_key.decrypt(blob, padding.PKCS1v15())


def new_record_key():
    return ChaCha20Poly1305.generate_key()


def store_password(pw: bytes) -> bytes:
    return bcrypt.hashpw(pw, bcrypt.gensalt())
