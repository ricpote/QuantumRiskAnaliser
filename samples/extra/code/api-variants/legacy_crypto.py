"""Python crypto API variants seen in real projects (pycryptodomex, hashlib.new, bare hash objects, small curves)."""
import hashlib

from Cryptodome.Cipher import ARC2
from Cryptodome.Hash import SHA3_256
from Cryptodome.PublicKey import RSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec


def legacy_cipher(key):
    return ARC2.new(key, ARC2.MODE_CBC)


def legacy_signing_key():
    return RSA.generate(bits=1024)


def file_id(data):
    return hashlib.new(name="md5", data=data).hexdigest()


def cache_bucket(data):
    # declared non-security use (Python >= 3.9): inventoried, not a vulnerability
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def modern_digest(data):
    return SHA3_256.new(data).hexdigest()


def legacy_hash_object():
    return hashes.SHA1()


def small_curve_key():
    return ec.generate_private_key(curve=ec.SECP192R1)


def legacy_dsa_key():
    return dsa.generate_private_key(key_size=1024)
