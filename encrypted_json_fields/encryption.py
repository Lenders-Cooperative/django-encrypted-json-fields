"""Encryption module for handling multiple encryption methods."""

from ast import literal_eval
import base64

from abc import ABC, abstractmethod
from enum import Enum
from json import JSONEncoder, JSONDecoder
from typing import Dict, Type, Union
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .aes import MultiAES
from .constants import EncryptionTypes


class EncryptionInterface(ABC):
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

    _encryption_registry: Dict[str, Type["EncryptionInterface"]] = {}

    def __init__(
        self,
        keys: Dict[str, list[bytes]],
        encoder: Type[JSONEncoder] | None = None,
        decoder: Type[JSONDecoder] | None = None,
        force: bool = True,
    ) -> None:
        """
        Initialize the encryption engine with encryption keys and optional JSON (de)serializers.

        The `keys` argument must be a dictionary containing lists of keys for each supported
        encryption method. For example:

            {
                "aes": [b"...", b"..."],
                "fernet": [b"..."],
                "aes_gcm": [b"..."]
            }

        Args:
            keys (dict): A dictionary of encryption keys.
            encoder (Type[JSONEncoder], optional): Encoder for encoding data during encryption.
            decoder (Type[JSONDecoder], optional): Decoder for decoding data during decryption.
            force (bool, optional): Whether to enforce encryption even if disabled globally. Defaults to True.

        Raises:
            ImproperlyConfigured: If no keys are provided or if keys are not in the expected format.
        """
        if not keys:
            raise ImproperlyConfigured("Encryption keys must be provided.")
        if not isinstance(keys, dict):
            raise ImproperlyConfigured("Encryption keys must be a dictionary.")

        self.keys = keys
        self.encoder = encoder or JSONEncoder
        self.decoder = decoder or JSONDecoder
        self.force = force
        if hasattr(settings, "EJF_ENABLE_ENCRYPTION"):
            self.encryption_enabled = settings.EJF_ENABLE_ENCRYPTION or force
        elif hasattr(settings, "SECURITY_SETTINGS"):
            self.encryption_enabled = settings.SECURITY_SETTINGS.get("EJF_ENABLE_ENCRYPTION") or force
        else:
            self.encryption_enabled = True  # Default to True if no setting is defined

    @classmethod
    def register_encryption_method(cls, method_type: Enum, encryption_class: Type["EncryptionInterface"]) -> None:
        """Register a new encryption method.

        Args:
            method_type (Enum): The type of the encryption method (e.g., AES, Fernet).
            encryption_class (Type["EncryptionInterface"]): The encryption class implementing the method.
        """
        cls._encryption_registry[method_type.value] = encryption_class

    @classmethod
    def get_encryption_registry(cls) -> Dict[str, Type["EncryptionInterface"]]:
        """Get the registry of all registered encryption methods.

        Returns:
            Dict[str, Type["EncryptionInterface"]]: A dictionary mapping method prefixes to their encryption classes.
        """
        return cls._encryption_registry

    @property
    @abstractmethod
    def method_type(self) -> EncryptionTypes:
        """Must return the type of the encryption method.

        E.g., EncryptionTypes.AES, EncryptionTypes.FERNET.
        """
        raise NotImplementedError("method_type not implemented")

    @property
    def prefix(self) -> bytes:
        """Builds the prefix for the encryption method.

        E.g., 'aes' -> b'aes:', 'fernet' -> b'fernet:'.

        Returns:
            bytes: The byte prefix for the encryption method.
        """
        return self.build_prefix(self.method_type)

    @abstractmethod
    def encrypt_raw(self, data: bytes) -> bytes:
        """Encrypts the raw data.

        Args:
            data (bytes): The plaintext data to encrypt.

        Raises:
            NotImplementedError: If the method is not implemented in the subclass.

        Returns:
            bytes: The encrypted data.
        """
        raise NotImplementedError("encrypt_raw method not implemented")

    @abstractmethod
    def decrypt_internal(self, data: bytes) -> bytes:
        """Decrypts the internal representation of the data.

        Args:
            data (bytes): The encrypted data to decrypt.

        Raises:
            NotImplementedError: If the method is not implemented in the subclass.

        Returns:
            bytes: The decrypted plaintext data.
        """
        raise NotImplementedError("decrypt_internal method not implemented")

    @abstractmethod
    def final_encrypt(self, data: bytes) -> bytes:
        """Finalizes the encryption process.

        Adds the prefix and encodes the data in a way that is consistent with the encryption method being used.
        E.g.:
            - Fernet: prefix + token (no re-encode)
            - AES: prefix + urlsafe_b64encode(raw)

        Args:
            data (bytes): The raw data to encrypt.

        Raises:
            NotImplementedError: If the method is not implemented in the subclass.

        Returns:
            bytes: The final encrypted data.
        """
        raise NotImplementedError("final_encrypt method not implemented")

    def encrypt(self, data: bytes) -> bytes:
        """Encrypts the raw data.

        Args:
            data (bytes): The raw data to encrypt.

        Returns:
            bytes: The encrypted data.
        """
        if not self.encryption_enabled:
            return data

        # Each subclass will handle final encoding/prefix steps differently
        return self.final_encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypts the encrypted data.

        Args:
            data (bytes): The encrypted data to decrypt.

        Raises:
            ValueError: If the data has an invalid prefix.

        Returns:
            bytes: The decrypted plaintext data.
        """
        if not self.encryption_enabled:
            return data

        # Check if data is already prefixed with this encryption method
        if data.startswith(self.prefix):
            without_prefix = data[len(self.prefix) :]
            return self.decrypt_internal(without_prefix)

        # Check against all registered encryption methods, for backwards compatibility
        for enc_type, enc_class in self.get_encryption_registry().items():
            enc_prefix = self.build_prefix(EncryptionTypes(enc_type))
            if data.startswith(enc_prefix):
                without_prefix = data[len(enc_prefix) :]
                return enc_class(self.keys).decrypt_internal(without_prefix)

        # If no prefix matches, assume legacy Fernet format
        try:
            return FernetEncryption(self.keys).decrypt_internal(data)
        except InvalidToken as e:
            raise ValueError("Invalid prefix or data format for encrypted data.") from e

    def is_encrypted(self, data: Union[str, bytes]) -> bool:
        """Checks if the provided data is encrypted.

        Args:
            data (Union[str, bytes]): The data to check.

        Returns:
            bool: True if the data is encrypted, False otherwise.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        # Check if data is already prefixed with this encryption method
        if data.startswith(self.prefix):
            return True

        # Check against all registered encryption methods, for backwards compatibility
        for enc_type in self.get_encryption_registry():
            enc_prefix = self.build_prefix(EncryptionTypes(enc_type))
            if data.startswith(enc_prefix):
                return True

        # If no prefix matches, assume legacy Fernet format
        return FernetEncryption(self.keys).is_encrypted_internal(data)

    def encrypt_str(self, s: str) -> str:
        """Encrypts a string.

        Args:
            s (str): The string to encrypt.

        Returns:
            str: The encrypted string.
        """
        if not self.encryption_enabled or self.is_encrypted(s.encode("utf-8")):
            return s

        encrypted = self.encrypt(s.encode("utf-8"))
        return encrypted.decode("utf-8")

    def decrypt_str(self, value: str) -> str:
        """Decrypts a string.

        Args:
            value (str): The string to decrypt.

        Returns:
            str: The decrypted string.
        """
        if not self.encryption_enabled:
            return value

        decrypted = self.decrypt(value.encode("utf-8"))
        return decrypted.decode("utf-8")

    def encrypt_values(
        self,
        data: Union[dict, list, set, tuple, int, float, str, bool],
        json_skip_keys: Union[list, tuple, set, None] = None,
        encoder: Type[JSONEncoder] | None = None,
    ) -> Union[dict, list, set, tuple, int, float, str, bool]:
        """
        Recursively encrypts values in a data structure. Used for encrypting JSONField data.

        Args:
            data (Union[dict, list, set, tuple, int, float, str, bool]): The data to encrypt.
            json_skip_keys (list, optional): Keys to skip during encryption.
            encoder (Type[JSONEncoder], optional): JSON encoder for complex types.

        Returns:
            Union[dict, list, set, tuple, int, float, str, bool]: The encrypted data.
        """
        if not self.encryption_enabled:
            return data

        if json_skip_keys is None:
            json_skip_keys = []

        if isinstance(data, (list, tuple, set)):
            return [self.encrypt_values(x, json_skip_keys, encoder) for x in data]

        if isinstance(data, dict):
            return {
                key: (value if key in json_skip_keys else self.encrypt_values(value, json_skip_keys, encoder))
                for key, value in data.items()
            }

        if type(data) in (int, float, bool, str):
            try:
                encoded_data = repr(data)
                return self.encrypt_str(encoded_data)
            except Exception as e:
                raise ValueError(f"Failed to encrypt value: {data} (Error: {e}).") from e

        try:
            encoded_data = (encoder or self.encoder)().encode(data)
            return self.encrypt_str(encoded_data)
        except Exception as e:
            raise ValueError(f"Failed to encode and encrypt value: {data} (Error: {e}).") from e

    def decrypt_values(
        self,
        data: Union[dict, list, set, tuple, str],
        decoder: Type[JSONDecoder] | None = None,
    ) -> Union[bool, int, float, str, None] | Union[dict, list, set, tuple, str]:
        """
        Recursively decrypts values in a data structure. Used for decrypting JSONField data.

        Args:
            data (Union[dict, list, set, tuple, str]): The data to decrypt.
            decoder (Type[JSONDecoder], optional): JSON decoder for complex types.

        Returns:
            Union[bool, int, float, str, None] | Union[dict, list, set, tuple, str]: The decrypted data.
        """
        if not self.encryption_enabled:
            return data

        if isinstance(data, (list, tuple, set)):
            return [self.decrypt_values(x) for x in data]

        if isinstance(data, dict):
            return {key: self.decrypt_values(value) for key, value in data.items()}

        if not isinstance(data, str) or not self.is_encrypted(data):
            return data

        decrypted_data = self.decrypt_str(data)

        try:
            return literal_eval(decrypted_data)
        except (ValueError, SyntaxError):
            return (decoder or self.decoder)().decode(decrypted_data)

    # --------------
    # Static methods
    # --------------

    @staticmethod
    def build_prefix(method_type: Enum) -> bytes:
        """Builds a prefix for the encryption method.

        This prefix is used to identify the encryption method used for the data.
        E.g. 'aes' -> b'aes:', 'fernet' -> b'fernet:'.

        Args:
            method_type (Enum): The type of the encryption method.

        Returns:
            bytes: The byte prefix for the encryption method.
        """
        return f"{method_type.value}:".encode("utf-8")


class NoEncryption(EncryptionInterface):
    """
    Implements no encryption (plaintext) storage.

    This is useful for testing, migrations or when encryption is not needed.
    """

    method_type = EncryptionTypes.NONE

    def encrypt_raw(self, data: bytes) -> bytes:
        """Encrypt data without any encryption.

        Args:
            data (bytes): Data to encrypt.

        Returns:
            bytes: Unmodified data.
        """
        return data

    def final_encrypt(self, data: bytes) -> bytes:
        """Encrypt data and add a prefix.

        Args:
            data (bytes): Data to encrypt.

        Returns:
            bytes: Prefixed unencrypted data.
        """
        return data

    def decrypt_internal(self, data: bytes) -> bytes:
        """Decrypt data without any encryption.

        Args:
            data (bytes): Data to decrypt.

        Returns:
            bytes: Unmodified data.
        """
        return data


class FernetEncryption(EncryptionInterface):
    """
    Implements Fernet symmetric encryption protocol.

    Fernet provides secure encryption using AES in CBC mode with a 128-bit key and HMAC-SHA256 for authentication.
    It ensures that encrypted messages cannot be read or tampered with without the key.
    """

    method_type = EncryptionTypes.FERNET

    def __init__(self, keys: dict[str, list[bytes]]) -> None:
        """
        Initialize FernetEncryption with Fernet keys.

        Args:
            keys (dict[str, list[bytes]]): Dictionary containing Fernet keys.

        Raises:
            ValueError: If no Fernet keys are provided or if any key is invalid.
        """
        super().__init__(keys)
        if not keys.get(self.method_type.value):
            raise ValueError("Fernet encryption requires at least one Fernet key.")

        try:
            self.crypter = MultiFernet([Fernet(base64.urlsafe_b64encode(key)) for key in keys[self.method_type.value]])
        except Exception as excp:
            raise ValueError(f"Invalid Fernet key: {excp}.") from excp

    def encrypt_raw(self, data: bytes) -> bytes:
        """
        Encrypt data using Fernet.

        Args:
            data (bytes): Data to encrypt.

        Returns:
            bytes: Fernet token (URL-safe base64 encoded).
        """
        return self.crypter.encrypt(data)

    def decrypt_internal(self, data: bytes) -> bytes:
        """
        Decrypt a Fernet token.

        Args:
            data (bytes): Fernet token to decrypt.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            InvalidToken: If the token is invalid or tampered with.
        """
        return self.crypter.decrypt(data)

    def is_encrypted_internal(self, data: bytes) -> bool:
        """
        Check if the provided data is a valid Fernet token.

        Args:
            data (bytes): Data to check.

        Returns:
            bool: True if valid Fernet token, False otherwise.

        Notes:
            Attempts to decrypt with infinite TTL to verify validity.
        """
        try:
            self.crypter.decrypt(data, ttl=None)

            return True
        except InvalidToken:
            return False

    def final_encrypt(self, data: bytes) -> bytes:
        """
        Add Fernet prefix to encrypted data.
        Respects PREFIX_FERNET_ALGO_POST_ENCRYPTION to decide whether to add the prefix.

        Args:
            data (bytes): Raw data to encrypt.

        Returns:
            bytes: Prefixed Fernet token.

        Notes:
            Prefix allows identification of encryption method in multi-method systems.
        """
        add_prefix = getattr(settings, "PREFIX_FERNET_ALGO_POST_ENCRYPTION", True)
        raw_encrypted = self.encrypt_raw(data)
        return self.prefix + raw_encrypted if add_prefix else raw_encrypted


class AESEncryption(EncryptionInterface):
    """
    Implements encryption using AES (Advanced Encryption Standard).

    Supports multiple AES modes (CBC, GCM, etc.) via MultiAES handler.
    """

    def __init__(self, keys: dict[str, list[bytes]]) -> None:
        """Initialize AESEncryption with AES keys and mode.

        Args:
            keys (dict[str, list[bytes]]): Dictionary containing AES keys for the selected mode.

        Raises:
            ValueError: If no keys are provided for the selected AES mode.
        """
        super().__init__(keys)
        if not keys.get(self.method_type.value):
            raise ValueError(f"AES encryption requires at least one {self.method_type.value} key.")

        self.crypter = MultiAES(keys[self.method_type.value], self.method_type.value)

    def encrypt_raw(self, data: bytes) -> bytes:
        """Encrypt raw data using AES.

        Args:
            data (bytes): Data to encrypt.

        Returns:
            bytes: Encrypted data in the format:
                - For CBC: iv + ciphertext + hmac_tag
                - For GCM: nonce + ciphertext + tag
        """
        return self.crypter.encrypt(data)

    def decrypt_internal(self, data: bytes) -> bytes:
        """Decrypts the raw data using AES.

        Args:
            data (bytes): Encrypted data to decrypt.

        Returns:
            bytes: Decrypted plaintext.
        """
        raw_encrypted = base64.urlsafe_b64decode(data)
        return self.crypter.decrypt(raw_encrypted)

    def final_encrypt(self, data: bytes) -> bytes:
        """Final encryption step for AES.

        Args:
            data (bytes): Raw data to encrypt.

        Returns:
            bytes: Prefixed encrypted data in format: prefix + AES token.
        """
        raw_encrypted = self.encrypt_raw(data)
        encoded = base64.urlsafe_b64encode(raw_encrypted)
        return self.prefix + encoded


class AESCBCEncryption(AESEncryption):
    """Implementation of encryption using AES in CBC mode."""

    method_type = EncryptionTypes.AES_CBC


class AESGCMEncryption(AESEncryption):
    """Implementation of encryption using AES in GCM mode."""

    method_type = EncryptionTypes.AES_GCM


EncryptionInterface.register_encryption_method(EncryptionTypes.AES_CBC, AESCBCEncryption)
EncryptionInterface.register_encryption_method(EncryptionTypes.AES_GCM, AESGCMEncryption)
EncryptionInterface.register_encryption_method(EncryptionTypes.FERNET, FernetEncryption)
