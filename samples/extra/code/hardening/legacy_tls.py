"""Transport helpers for the legacy partner gateway."""
import crypt
import ssl

from cryptography.hazmat.primitives.ciphers import modes


def client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
    return ctx


def legacy_socket(sock):
    return ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)


def is_legacy(ctx):
    return ctx.protocol == ssl.PROTOCOL_TLSv1


def store_password(password):
    return crypt.crypt(password, crypt.mksalt(crypt.METHOD_MD5))


def record_mode():
    return modes.ECB()


from ssl import PROTOCOL_TLSv1_1
from OpenSSL import SSL
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

new_rsa_key = rsa.generate_private_key


def partner_socket(sock):
    return ssl.wrap_socket(sock, ssl_version=PROTOCOL_TLSv1_1)


def pinned_context():
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
    return ctx


def signing_key():
    return new_rsa_key(65537, 1024)


def stream(key, data):
    algorithm = algorithms.ARC4(key)
    return Cipher(algorithm, mode=None).encryptor().update(data)


def hash_password(password):
    h = hashes.Hash(hashes.SHA256())
    h.update(password)
    return h.finalize()
