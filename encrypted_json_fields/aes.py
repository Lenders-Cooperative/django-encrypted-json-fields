"""
AES encryption mode handlers and crypters.

Defines abstract and concrete classes for AES encryption and decryption
using CBC and GCM modes, leveraging the cryptography library.

See: https://cryptography.io/en/latest/
"""

import os

from abc import ABC, abstractmethod
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import EncryptionTypes


# -----------
# AES Crypter
# -----------


class MultiAES:
    """Crypter for handling multiple AES keys and modes."""

    def __init__(self, keys: list[bytes], mode: str) -> None:
        """Initialize the MultiAES crypter with multiple keys and a mode.

        Args:
            keys (list[bytes]): List of AES keys.
            mode (str): AES mode (e.g., "CBC", "GCM").

        Raises:
            ValueError: If the keys are not valid AES keys.
            ValueError: If the mode is not supported.
        """
        if any(len(key) != 32 for key in keys):
            raise ValueError("All AES keys must be 256 bits (32 bytes).")
        if mode not in MODE_REGISTRY:
            raise ValueError(f"AES mode '{mode}' is not supported.")

        self.keys = keys
        self.handler = MODE_REGISTRY[mode]

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts the given plaintext using the configured AES mode.

        Args:
            plaintext (bytes): The plaintext data to encrypt.

        Returns:
            bytes: The encrypted ciphertext.
        """
        key = self.keys[0]  # Use the first (primary) key for encryption
        return self.handler.encrypt(key, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts the given ciphertext using the configured AES mode.

        Args:
            ciphertext (bytes): The ciphertext data to decrypt.

        Raises:
            ValueError: If decryption fails with all keys.

        Returns:
            bytes: The decrypted plaintext.
        """
        for key in self.keys:
            try:
                return self.handler.decrypt(key, ciphertext)
            except (InvalidSignature, InvalidTag, ValueError):
                continue

        raise ValueError("Decryption failed with all keys.")


# -------------------------
# Abstract AES mode handler
# -------------------------


class AESModeHandler(ABC):
    """Abstract base class for AES mode handlers.

    Args:
        ABC (ABC): Abstract base class for AES mode handlers.
    """

    @abstractmethod
    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypts plaintext using AES.

        Args:
            key (bytes): Encryption key.
            plaintext (bytes): Plaintext to encrypt.

        Returns:
            bytes: Encrypted ciphertext.
        """

    @abstractmethod
    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """Decrypts ciphertext using AES.

        Args:
            key (bytes): Decryption key.
            ciphertext (bytes): Ciphertext to decrypt.

        Returns:
            bytes: Decrypted plaintext.
        """


# --------------------------
# Concrete AES mode handlers
# --------------------------


class CBCModeHandler(AESModeHandler):
    """Handles AES encryption in CBC mode.

    Args:
        AESModeHandler (ABC): Abstract base class for AES mode handlers.
    """

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypts plaintext using AES CBC mode.

        Args:
            key (bytes): Encryption key.
            plaintext (bytes): Plaintext to encrypt.

        Returns:
            bytes: Concatenated IV, ciphertext, and HMAC tag.
        """
        block_size = 16

        padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes for AES
        padded_data = padder.update(plaintext) + padder.finalize()

        iv = os.urandom(block_size)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(iv + ciphertext)
        hmac_tag = h.finalize()

        return iv + ciphertext + hmac_tag

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """Decrypts ciphertext using AES CBC mode.

        Args:
            key (bytes): Decryption key.
            ciphertext (bytes): Ciphertext to decrypt.

        Raises:
            ValueError: If the ciphertext is invalid.

        Returns:
            bytes: Decrypted plaintext.
        """
        block_size = 16
        if len(ciphertext) < block_size + 32:
            raise ValueError("Ciphertext too short for CBC")

        iv = ciphertext[:block_size]
        ct = ciphertext[block_size:-32]
        hmac_tag = ciphertext[-32:]

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(iv + ct)
        h.verify(hmac_tag)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()  # 128 bits = 16 bytes for AES
        decrypted = unpadder.update(padded_data) + unpadder.finalize()

        return decrypted


class GCMModeHandler(AESModeHandler):
    """Handles AES encryption in GCM mode.

    Args:
        AESModeHandler (ABC): Abstract base class for AES mode handlers.
    """

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypts plaintext using AES GCM mode.

        Args:
            key (bytes): Encryption key.
            plaintext (bytes): Plaintext to encrypt.

        Returns:
            bytes: Concatenated nonce and ciphertext.
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return nonce + ciphertext

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """Decrypts ciphertext using AES GCM mode.

        Args:
            key (bytes): Encryption key.
            ciphertext (bytes): Concatenated nonce and ciphertext.

        Returns:
            bytes: Decrypted plaintext.
        """
        nonce, ct = ciphertext[:12], ciphertext[12:]
        aesgcm = AESGCM(key)

        return aesgcm.decrypt(nonce, ct, None)


# Registering the AES modes
MODE_REGISTRY: dict[str, AESModeHandler] = {
    EncryptionTypes.AES_CBC.value: CBCModeHandler(),
    EncryptionTypes.AES_GCM.value: GCMModeHandler(),
}
