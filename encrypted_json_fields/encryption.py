from abc import ABC, abstractmethod
import json
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from typing import Dict, List, Type, Union
import base64
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os
from Crypto.Util.Padding import pad, unpad
from .constants import AES_PREFIX, FERNET_PREFIX

class MultiAES:
    def __init__(self, keys: List[bytes]) -> None:
        for key in keys:
            if len(key) != 32:
                raise ValueError("Invalid AES key length: must be 32 bytes.")
        self.keys = keys

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using AES-CBC with the most recent key and HMAC authentication.

        Args:
            plaintext (bytes): The data to encrypt.

        Returns:
            bytes: Concatenated IV + encrypted data + HMAC tag.
                  Format: [16 bytes IV][variable length ciphertext][32 bytes HMAC]

        Notes:
            - Uses the last key in the keys list for encryption
            - Generates a random IV for each encryption
            - Includes HMAC-SHA256 for integrity verification
        """
        key = self.keys[-1]
        block_size = 16
        iv = os.urandom(block_size)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padded_data = pad(plaintext, block_size)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(iv + ciphertext)
        hmac_tag = h.finalize()

        return iv + ciphertext + hmac_tag

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using AES-CBC, trying all available keys until successful.

        Args:
            ciphertext (bytes): The encrypted data in format [IV][ciphertext][HMAC].
                               Must be at least 48 bytes long (16 byte IV + 32 byte HMAC).

        Returns:
            bytes: The decrypted plaintext.

        Raises:
            ValueError: If decryption fails with all available keys or if the input is invalid.

        Notes:
            - Attempts decryption with each key until successful
            - Verifies HMAC before attempting decryption
            - Uses CBC mode with the IV from the ciphertext
        """
        block_size = 16
        for key in self.keys:
            try:
                iv = ciphertext[:block_size]
                cipher_text_only = ciphertext[block_size:-32]
                hmac_tag = ciphertext[-32:]
                h = hmac.HMAC(key, hashes.SHA256())
                h.update(iv + cipher_text_only)
                h.verify(hmac_tag)

                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(cipher_text_only) + decryptor.finalize()
                return unpad(padded_data, block_size)
            except (InvalidSignature, ValueError):
                continue
        raise ValueError("Decryption failed with all keys")

class EncryptionMethod(ABC):
    """
    Abstract base class for encryption methods. Provides a flexible interface
    for handling multiple encryption schemes like AES and Fernet.

    Attributes:
        _encryption_registry (dict): A registry of encryption methods keyed by their prefixes.
        keys (dict): A dictionary of encryption keys.
        aes_keys (list): List of AES encryption keys.
        fernet_keys (list): List of Fernet encryption keys.
        encoder: JSON encoder for encoding data during encryption.
        decoder: JSON decoder for decoding data during decryption.
        force (bool): Whether to enforce encryption even if disabled globally.
        encryption_enabled (bool): Whether encryption is enabled globally or forced.
    """

    _encryption_registry: Dict[bytes, Type["EncryptionMethod"]] = {}

    def __init__(self, keys, encoder=None, decoder=None, force=True):
        """
        Initializes the encryption method with the required keys and settings.

        Args:
            keys (dict): A dictionary of encryption keys (e.g., {"aes": [...], "fernet": [...]}).
            encoder (json.JSONEncoder, optional): JSON encoder for encoding data.
            decoder (json.JSONDecoder, optional): JSON decoder for decoding data.
            force (bool, optional): Force encryption even if globally disabled.

        Raises:
            ImproperlyConfigured: If keys are not provided or not a dictionary.
        """
        if not keys:
            raise ImproperlyConfigured("Encryption keys must be provided during initialization.")
        if not isinstance(keys, dict):
            raise ImproperlyConfigured("Keys must be provided as a dictionary.")
        self.keys = keys
        self.encoder = encoder or json.JSONEncoder()
        self.decoder = decoder or json.JSONDecoder()
        self.force = force
        self.encryption_enabled = getattr(settings, "EJF_ENABLE_ENCRYPTION", True) or force

    @classmethod
    def register_encryption_method(cls, prefix: bytes, encryption_class: type):
        cls._encryption_registry[prefix] = encryption_class

    @abstractmethod
    def _encrypt_raw(self, data: bytes) -> bytes:
        raise NotImplementedError("_encrypt_raw method not implemented")

    @abstractmethod
    def _decrypt_internal(self, data: bytes) -> bytes:
        raise NotImplementedError("_decrypt_internal method not implemented")

    @property
    @abstractmethod
    def prefix(self) -> bytes:
        raise NotImplementedError("prefix property not implemented")

    def _is_legacy_data(self, data: bytes) -> bool:
        # No prefix => legacy Fernet token
        fernet_encryption = FernetEncryption(self.keys)
        return fernet_encryption._is_encrypted_internal(data)

    def encrypt(self, data: bytes) -> bytes:
        if not self.encryption_enabled:
            return data
        # Each subclass will handle final encoding/prefix steps differently
        return self._final_encrypt(data)

    @abstractmethod
    def _final_encrypt(self, data: bytes) -> bytes:
        """
        Finalize encryption:
        - Fernet: prefix + token (no re-encode)
        - AES: prefix + urlsafe_b64encode(raw)
        """
        raise NotImplementedError("_final_encrypt method not implemented")

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts the provided data.

        Args:
            data (bytes): The encrypted data to decrypt.

        Returns:
            bytes: The decrypted plaintext data.

        Raises:
            ValueError: If the data has an invalid prefix.
        """
        if not self.encryption_enabled:
            return data

        for prefix, enc_class in self._encryption_registry.items():
            if data.startswith(prefix):
                crypter = enc_class(self.keys)
                without_prefix = data[len(prefix):]
                return crypter._decrypt_internal(without_prefix)

        # No prefix => legacy Fernet
        try:
            fernet_encryption = FernetEncryption(self.keys)
            return fernet_encryption._decrypt_internal(data)
        except InvalidToken:
            raise ValueError(
                "Invalid prefix or data format for encrypted data")

    def _decrypt_legacy(self, data: bytes) -> bytes:
        fernet_encryption = FernetEncryption(self.keys)
        return fernet_encryption.crypter.decrypt(data)

    def is_encrypted(self, data: Union[str, bytes]) -> bool:
        if isinstance(data, str):
            data = data.encode("utf-8")

        for prefix, enc_class in self._encryption_registry.items():
            if data.startswith(prefix):
                return True
        # No prefix => legacy Fernet
        return self._is_legacy_data(data)

    def encrypt_str(self, s: str) -> str:
        if not self.encryption_enabled or self.is_encrypted(s.encode("utf-8")):
            return s
        encrypted = self.encrypt(s.encode("utf-8"))
        return encrypted.decode("utf-8")

    def decrypt_str(self, value: str) -> str:
        if not self.encryption_enabled:
            return value

        decrypted = self.decrypt(value.encode("utf-8"))
        return decrypted.decode("utf-8")

    def encrypt_values(self, data, json_skip_keys=None, encoder=None):
        """
        Recursively encrypts values in a data structure. Used for encrypting JSONField data.

        Args:
            data (Union[dict, list, set, tuple, int, float, str, bool]): The data to encrypt.
            json_skip_keys (list, optional): Keys to skip during encryption.
            encoder (json.JSONEncoder, optional): JSON encoder for complex types.

        Returns:
            Union[dict, list, set, tuple, int, float, str, bool]: The encrypted data.
        """
        if not self.encryption_enabled:
            return data

        if json_skip_keys is None:
            json_skip_keys = []

        if isinstance(data, (list, tuple, set)):
            return [self.encrypt_values(x, json_skip_keys=json_skip_keys,
                                        encoder=encoder) for x in data]

        if isinstance(data, dict):
            return {
                key: value if key in json_skip_keys else self.encrypt_values(
                    value, json_skip_keys=json_skip_keys, encoder=encoder)
                for key, value in data.items()
            }

        if isinstance(data, (int, float, bool, str)):
            try:
                encoded_data = repr(data)
                return self.encrypt_str(encoded_data)
            except Exception as e:
                raise ValueError(
                    f"Failed to encrypt value: {data} (Error: {str(e)})")

        try:
            encoder_obj = encoder() if encoder else json.JSONEncoder()
            encoded_data = encoder_obj.encode(data)
            return self.encrypt_str(encoded_data)
        except Exception as e:
            raise ValueError(
                f"Failed to encode and encrypt value: {data} (Error: {str(e)})")

    def decrypt_values(self, data):
        """
        Recursively decrypts values in a data structure. Used for decrypting JSONField data.

        Args:
            data (Union[dict, list, set, tuple, str]): The data to decrypt.

        Returns:
            Union[dict, list, set, tuple, str]: The decrypted data.
        """
        if not self.encryption_enabled:
            return data

        if isinstance(data, (list, tuple, set)):
            return [self.decrypt_values(x) for x in data]

        if isinstance(data, dict):
            return {key: self.decrypt_values(value) for key, value in data.items()}

        if not isinstance(data, str):
            return data

        if not self.is_encrypted(data):
            return data

        decrypted_data = self.decrypt_str(data)

        try:
            return self.infer_type(decrypted_data)
        except (ValueError, SyntaxError):
            return self.decoder.decode(decrypted_data)

    def infer_type(self, value):
        """Try to infer the correct type of the decrypted string value.
           Using this to avoid literal_eval
        """
        if value is None:
            return None  # Explicitly handle None

        if isinstance(value, str):
            value = value.strip()  # Remove leading/trailing whitespace

            # Remove surrounding single or double quotes if they exist
            if (value.startswith("'") and value.endswith("'")) or (
                value.startswith('"') and value.endswith('"')):
                value = value[1:-1]

            # Check for booleans
            if value.lower() == "true":
                return True
            if value.lower() == "false":
                return False

            # Check for integers
            try:
                return int(value)
            except ValueError:
                pass

            # Check for floats
            try:
                return float(value)
            except ValueError:
                pass

        # Return as string or the original value if no conversions apply
        return value


class FernetEncryption(EncryptionMethod):
    """
    Implementation of encryption using the Fernet symmetric encryption protocol.

    Fernet guarantees that a message encrypted using it cannot be manipulated or
    read without the key. It uses AES in CBC mode with a 128-bit key for encryption
    and HMAC using SHA256 for authentication.
    """
    prefix = FERNET_PREFIX

    def __init__(self, keys):
        super().__init__(keys)
        self.fernet_keys = keys.get("fernet", [])
        try:
            self.crypter = MultiFernet([Fernet(key) for key in self.fernet_keys])
        except Exception as e:
            raise ValueError(f"Invalid Fernet key: {e}")

    def _encrypt_raw(self, data: bytes) -> bytes:
        # Returns Fernet token directly (URL-safe base64)
        return self.crypter.encrypt(data)

    def _decrypt_internal(self, data: bytes) -> bytes:
        """
        Decrypt a Fernet token.

        Args:
            data (bytes): Encrypted data as a Fernet token.

        Returns:
            bytes: Decrypted data.

        Raises:
            InvalidToken: If the token is invalid or has been tampered with.
        """
        return self.crypter.decrypt(data)

    def _is_encrypted_internal(self, data: bytes) -> bool:
        """
        Check if the provided data is a valid Fernet-encrypted token.

        Args:
            data (bytes): Data to check.

        Returns:
            bool: True if the data is a valid Fernet token, False otherwise.

        Notes:
            This method attempts to decrypt the data with an infinite TTL to
            verify if it's a valid Fernet token, regardless of age.
        """
        try:
            self.crypter.decrypt(data, ttl=None)
            return True
        except InvalidToken:
            return False

    def _final_encrypt(self, data: bytes) -> bytes:
        """
        Perform final encryption step by adding the encryption method prefix.

        Args:
            data (bytes): Raw data to encrypt.

        Returns:
            bytes: Prefixed encrypted data in format: prefix + Fernet token.

        Notes:
            This method adds the Fernet prefix to identify the encryption method
            used, allowing for multiple encryption methods in the same system.
        """
        raw_encrypted = self._encrypt_raw(data)
        return self.prefix + raw_encrypted


class AESEncryption(EncryptionMethod):
    """
    Implementation of encryption using AES (Advanced Encryption Standard).

    This class provides AES encryption in CBC mode with HMAC authentication.
    The implementation includes support for multiple encryption keys and
    uses URL-safe base64 encoding for the final encrypted output.
    """
    prefix = AES_PREFIX

    def __init__(self, keys):
        """
        Initialize AESEncryption with encryption keys.

        Args:
            keys (dict): Dictionary containing encryption keys. Must include 'aes' key
                        with a list of 32-byte keys for AES-256 encryption.

        Raises:
            ImproperlyConfigured: If keys dictionary is empty or malformed.
            ValueError: If any AES key is not exactly 32 bytes long.
        """
        super().__init__(keys)
        self.aes_keys = keys.get("aes", [])
        self.crypter = MultiAES(self.aes_keys)

    def _encrypt_raw(self, data: bytes) -> bytes:
        # AES: raw binary
        return self.crypter.encrypt(data)

    def _decrypt_internal(self, data: bytes) -> bytes:
        raw_encrypted = base64.urlsafe_b64decode(data)
        return self.crypter.decrypt(raw_encrypted)

    def _final_encrypt(self, data: bytes) -> bytes:
        """
        Perform final encryption step and prepare data for storage/transmission.

        Args:
            data (bytes): Raw data to encrypt.

        Returns:
            bytes: Prefixed and encoded encrypted data in format:
                  prefix + base64url(IV + ciphertext + HMAC)

        Notes:
            - Encrypts the raw data using AES
            - Encodes the result using URL-safe base64
            - Prepends the AES prefix for identification
        """
        raw_encrypted = self._encrypt_raw(data)
        encoded = base64.urlsafe_b64encode(raw_encrypted)
        return self.prefix + encoded


EncryptionMethod.register_encryption_method(AES_PREFIX, AESEncryption)
EncryptionMethod.register_encryption_method(FERNET_PREFIX, FernetEncryption)
