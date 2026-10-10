"""Password storage and transport settings (Django / hashlib / ssl)."""
import hashlib
import ssl

from Crypto.Cipher import AES
from passlib.hash import pbkdf2_sha256

PASSWORD_HASHERS = ["django.contrib.auth.hashers.UnsaltedMD5PasswordHasher"]

FIXED_SALT = b"static-salt-v1"


def derive(password):
    return hashlib.pbkdf2_hmac("sha256", password, FIXED_SALT, 600000)


def derive_lazy(password):
    return hashlib.scrypt(password, salt=password, n=1 << 14, r=8, p=1)


def legacy_store(password):
    return pbkdf2_sha256.using().hash(password)


def short_id(blob):
    # an identifier, not a security digest
    return hashlib.md5(blob).hexdigest()[:8]


def seal(key, data):
    enc = AES.new(key, AES.MODE_CBC, b"\0" * 16)
    return enc.encrypt(data)


def open_box(key, iv, blob):
    # decryption must reuse the IV that came with the ciphertext: not reported
    dec = AES.new(key, AES.MODE_CBC, b"\0" * 16)
    return dec.decrypt(blob)


def legacy_tls():
    ctx = ssl.create_default_context()
    ctx.set_ciphers("ECDH+3DES:RSA+HIGH")
    return ctx
