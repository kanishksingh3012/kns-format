"""Turn a password into a key, and encrypt or decrypt one message. See SPEC.md.

This module knows nothing about the text layout of a .kns file. It works
on the header dictionaries and Block objects that kns.format produces.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .format import Block

CIPHER = "aes-256-gcm"
KDF = "pbkdf2-sha256"
ITERATIONS = 600_000
MAX_ITERATIONS = 10_000_000  # refuse files that would make us work forever
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32


class CryptoError(Exception):
    """The file cannot be decrypted."""


def new_file_header() -> dict[str, str]:
    """The header for a brand new file, with a fresh random salt."""
    return {
        "cipher": CIPHER,
        "kdf": KDF,
        "iterations": str(ITERATIONS),
        "salt": _encode(os.urandom(SALT_BYTES)),
    }


def derive_key(password: str, file_header: dict[str, str]) -> bytes:
    """Password + salt -> the 32-byte key. Slow on purpose."""
    if file_header["cipher"] != CIPHER:
        raise CryptoError(f"unsupported cipher '{file_header['cipher']}'")
    if file_header["kdf"] != KDF:
        raise CryptoError(f"unsupported kdf '{file_header['kdf']}'")
    iterations = file_header["iterations"]
    if not iterations.isascii() or not iterations.isdigit() or not 0 < int(iterations) <= MAX_ITERATIONS:
        raise CryptoError(f"iterations must be a whole number from 1 to {MAX_ITERATIONS}")
    salt = _decode(file_header["salt"], "salt", SALT_BYTES)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations), KEY_BYTES)


def encrypt_block(key: bytes, index: int, content: bytes, type="text", sender=None, date=None, name=None) -> Block:
    """Encrypt content as block number `index` (the first block is 1)."""
    header = {"type": type}
    if sender:
        header["from"] = sender
    if date:
        header["date"] = date
    if name:
        header["name"] = name
    nonce = os.urandom(NONCE_BYTES)
    header["nonce"] = _encode(nonce)
    ciphertext = AESGCM(key).encrypt(nonce, content, _associated_data(index, header))
    return Block(header=header, payload=_encode(ciphertext))


def decrypt_block(key: bytes, index: int, block: Block) -> bytes:
    """Decrypt block number `index`. Fails if anything about it was changed."""
    nonce = _decode(block.header["nonce"], "nonce", NONCE_BYTES)
    ciphertext = _decode(block.payload, "payload")
    if len(ciphertext) < TAG_BYTES:
        raise CryptoError(f"message {index}: payload is too short")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _associated_data(index, block.header))
    except InvalidTag:
        raise CryptoError(f"message {index}: wrong password, or the file was changed") from None


def _associated_data(index, header):
    # Not secret, but AES-GCM refuses to decrypt if any of it differs.
    parts = ["KNS1", str(index), header["type"], header.get("from", ""), header.get("date", "")]
    if "name" in header:
        parts.append(header["name"])
    return "\n".join(parts).encode("utf-8")


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(text, name, length=None):
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoError(f"{name} is not valid base64") from None
    if length is not None and len(data) != length:
        raise CryptoError(f"{name} must be {length} bytes, got {len(data)}")
    return data
