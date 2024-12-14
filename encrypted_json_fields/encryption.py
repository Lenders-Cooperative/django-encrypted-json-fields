from abc import ABC, abstractmethod
import json
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from typing import Union
import base64
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os
from ast import literal_eval
from .utils import pad, unpad
from .constants import AES_PREFIX, FERNET_PREFIX


class MultiAES:
    """
    MultiAES provides AES-256 encryption and decryption with support for multiple keys.
    All keys must be 32 bytes long.
    """
    def __init__(self, keys):
        """Initialize with multiple keys"""
        for key in keys:
            if len(key) != 32:  # AES-256 requires 32-byte keys
                raise ValueError("Invalid AES key length: must be 32 bytes.")
        self.keys = keys

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt the plaintext using AES-CBC with PKCS#7 padding and HMAC for authentication."""
        key = self.keys[-1]  # Use the latest key
        if len(key) != 32:
            raise ValueError(
                "AES key must be 32 bytes for AES-256 encryption.")

        block_size = 16  # AES block size
        iv = os.urandom(block_size)  # Generate a random IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Add PKCS#7 padding to the plaintext
        padded_data = pad(plaintext, block_size)

        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Create an HMAC for IV + ciphertext
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(iv + ciphertext)
        hmac_tag = h.finalize()

        # Return IV + ciphertext + HMAC tag
        return iv + ciphertext + hmac_tag

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Try to decrypt the ciphertext using any available key."""
        block_size = 16  # AES block size

        for key in self.keys:
            try:
                if len(key) != 32:
                    raise ValueError(
                        "AES key must be 32 bytes for AES-256 decryption.")

                # Extract components
                iv = ciphertext[:block_size]
                cipher_text_only = ciphertext[block_size:-32]
                hmac_tag = ciphertext[-32:]

                # Verify HMAC
                h = hmac.HMAC(key, hashes.SHA256())
                h.update(iv + cipher_text_only)
                h.verify(hmac_tag)

                # If HMAC is valid, decrypt the ciphertext
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(
                    cipher_text_only) + decryptor.finalize()

                # Remove PKCS#7 padding
                return unpad(padded_data, block_size)
            except (InvalidSignature, ValueError) as e:
                continue

        # If all keys fail
        raise ValueError("Decryption failed with all keys")


class EncryptionMethod(ABC):
    _encryption_registry = {}

    def __init__(self, keys, encoder=None, decoder=None, force=False):
        if not keys:
            raise ImproperlyConfigured("Encryption keys must be provided during initialization.")
        self.keys = keys
        self.encoder = encoder or json.JSONEncoder()
        self.decoder = decoder or json.JSONDecoder()
        self.force = force
        self.encryption_disabled = force or getattr(settings, "EJF_DISABLE_ENCRYPTION", False)

    @classmethod
    def register_encryption_method(cls, prefix: bytes, encryption_class: type):
        """
        Registers an encryption class with a specific prefix.
        """
        cls._encryption_registry[prefix] = encryption_class

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt the given data.
        """
        raise NotImplementedError("encrypt method not implemented")

    @abstractmethod
    def _decrypt_internal(self, data: bytes) -> bytes:
        """
        Internal method to decrypt the data.
        """
        raise NotImplementedError("_decrypt_internal method not implemented")

    @abstractmethod
    def _is_encrypted_internal(self, data: bytes) -> bool:
        """
        Internal method to check if the data is encrypted.
        """
        raise NotImplementedError("_is_encrypted_internal method not implemented")

    def _is_legacy_data(self, data: bytes) -> bool:
        """
        Determines if the given data qualifies as legacy (non-prefixed) encrypted data.
        Legacy data is assumed to be valid Fernet data without a prefix.
        """
        try:
            fernet_encryption = FernetEncryption(self.keys)
            return fernet_encryption._is_encrypted_internal(data)
        except Exception as excp:
            return False

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt the given data based on the prefix by dispatching to the registered encryption class.
        For legacy data without a prefix, defaults to Fernet decryption.
        Raises a ValueError for invalid prefixes.
        """
        if self.encryption_disabled:
            return data

        # Check for a valid prefix
        for prefix, encryption_class in self._encryption_registry.items():
            if data.startswith(prefix):
                crypter = encryption_class(self.keys)
                return crypter._decrypt_internal(data)

        # Check if the data is legacy (no prefix)
        if self._is_legacy_data(data):
            fernet_encryption = FernetEncryption(self.keys)
            return fernet_encryption._decrypt_internal(data)

        # Raise an error for unrecognized prefixes
        raise ValueError("Invalid prefix for encrypted data")

    def is_encrypted(self, data: Union[str, bytes]) -> bool:
        """
        Determines if the given data is encrypted by dispatching to the correct encryption class.
        Handles prefixed data, legacy (non-prefixed) data, and invalid prefixes.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        # Check for a valid prefix
        for prefix, encryption_class in self._encryption_registry.items():
            if data.startswith(prefix):
                crypter = encryption_class(self.keys)
                return crypter._is_encrypted_internal(data[len(prefix):])

        # Check if the data qualifies as legacy (non-prefixed) Fernet data
        if self._is_legacy_data(data):
            return True

        # No valid prefix and not legacy data
        return False

    def encrypt_str(self, s: str) -> str:
        """Encrypt the given string."""
        if self.encryption_disabled or self.is_encrypted(s.encode("utf-8")):
            return s
        return self.encrypt(s.encode("utf-8")).decode("utf-8")

    def decrypt_bytes(self, s: bytes) -> str:
        """
        Decrypt the given bytes data and return a string.
        """
        assert isinstance(s, bytes), "Input to decrypt_bytes must be bytes."

        if self.encryption_disabled:
            return s.decode("utf-8")

        try:
            return self.decrypt(s).decode("utf-8")
        except Exception:
            return str(s)

    def encrypt_values(self, data, json_skip_keys=None, encoder=None):
        """
        Recursively encrypt values in lists, tuples, sets, or dictionaries.
        """
        if self.encryption_disabled:
            return data

        if json_skip_keys is None:
            json_skip_keys = []

        # Handle lists, tuples, and sets recursively
        if isinstance(data, (list, tuple, set)):
            return [self.encrypt_values(x, json_skip_keys=json_skip_keys, encoder=encoder) for x in data]

        # Handle dictionaries recursively
        if isinstance(data, dict):
            return {
                key: value if key in json_skip_keys
                else self.encrypt_values(value, json_skip_keys=json_skip_keys,
                                         encoder=encoder)
                for key, value in data.items()
            }

        # Determine the encoder
        if encoder is None:
            encoder_obj = json.JSONEncoder()
        else:
            encoder_obj = encoder()

        # Handle primitive data types
        if isinstance(data, (int, float, bool, str)):
            try:
                # Represent the data as a string before encrypting
                encoded_data = repr(data)
                return self.encrypt_str(encoded_data)
            except Exception as e:
                raise ValueError(
                    f"Failed to encrypt value: {data} (Error: {str(e)})")

        # Handle non-primitive serializable data
        try:
            encoded_data = encoder_obj.encode(data)
            return self.encrypt_str(encoded_data)
        except Exception as e:
            raise ValueError(
                f"Failed to encode and encrypt value: {data} (Error: {str(e)})")

    def decrypt_values(self, data):
        """
        Recursively decrypt values in lists, tuples, sets, or dictionaries.
        """
        if self.encryption_disabled:
            return data

        # Handle lists, tuples, and sets recursively
        if isinstance(data, (list, tuple, set)):
            return [self.decrypt_values(x) for x in data]

        # Handle dictionaries recursively
        if isinstance(data, dict):
            return {key: self.decrypt_values(value) for key, value in
                    data.items()}

        # Handle primitive values
        try:
            if not isinstance(data, str):
                return data

            # Check if the data is encrypted
            if not self.is_encrypted(data):
                return data

            # Decrypt the data
            decrypted_data = self.decrypt_bytes(data.encode("utf-8"))

            # Attempt to parse the decrypted data
            try:
                # Try to convert back to original type
                return literal_eval(decrypted_data)
            except (ValueError, SyntaxError):
                # Fall back to JSON decoding
                return self.decoder.decode(decrypted_data)
        except Exception as e:
            # Provide clear error message
            raise ValueError(
                f"Failed to decrypt value: {data} (Error: {str(e)})")


class FernetEncryption(EncryptionMethod):
    def __init__(self, keys):
        super().__init__(keys)
        try:
            self.crypter = MultiFernet([Fernet(key) for key in keys])
        except Exception as e:
            raise ValueError(f"Invalid Fernet key: {e}")

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using Fernet and add the Fernet prefix."""
        if self.encryption_disabled:
            return data
        return FERNET_PREFIX + self.crypter.encrypt(data)

    def _decrypt_internal(self, data: bytes) -> bytes:
        """
        Decrypt Fernet-encrypted data.
        Handle both prefixed and legacy data without a prefix.
        """
        if data.startswith(FERNET_PREFIX):
            data = data[len(FERNET_PREFIX):]
        return self.crypter.decrypt(data)


    def _is_encrypted_internal(self, data: bytes) -> bool:
        """
        Check if the given data is encrypted using Fernet.
        Considers both prefixed and legacy (non-prefixed) data.
        """

        if data.startswith(FERNET_PREFIX):
            data = data[len(FERNET_PREFIX):]

        for fernet in self.crypter._fernets:
            try:
                decrypted_data = fernet.decrypt(data, ttl=None)  # Actual decryption attempt
                return True
            except InvalidToken:
                continue  # Try the next key
        return False



class AESEncryption(EncryptionMethod):
    def __init__(self, keys):
        super().__init__(keys)
        self.crypter = MultiAES(keys)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES and add the AES prefix."""
        if self.encryption_disabled:
            return data
        return AES_PREFIX + self.crypter.encrypt(data)

    def _decrypt_internal(self, data: bytes) -> bytes:
        """Decrypt AES-encrypted data."""
        if not data.startswith(AES_PREFIX):
            raise ValueError("Invalid prefix for AES-encrypted data")
        return self.crypter.decrypt(data[len(AES_PREFIX):])

    def _is_encrypted_internal(self, data: bytes) -> bool:
        """
        Check if the given data is encrypted using AES.
        """
        try:
            if not data.startswith(AES_PREFIX):
                return False
            data = data[len(AES_PREFIX):]
            return len(data) >= 48  # IV (16) + HMAC (32)
        except Exception:
            return False


EncryptionMethod.register_encryption_method(AES_PREFIX, AESEncryption)
EncryptionMethod.register_encryption_method(FERNET_PREFIX, FernetEncryption)
