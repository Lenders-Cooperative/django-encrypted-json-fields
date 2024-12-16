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
    def __init__(self, keys):
        for key in keys:
            if len(key) != 32:
                raise ValueError("Invalid AES key length: must be 32 bytes.")
        self.keys = keys

    def encrypt(self, plaintext: bytes) -> bytes:
        key = self.keys[-1]
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes.")
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
        block_size = 16
        for key in self.keys:
            try:
                if len(key) != 32:
                    raise ValueError("AES key must be 32 bytes.")
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
        cls._encryption_registry[prefix] = encryption_class

    @abstractmethod
    def _encrypt_raw(self, data: bytes) -> bytes:
        raise NotImplementedError("_encrypt_raw method not implemented")

    @abstractmethod
    def _decrypt_internal(self, data: bytes) -> bytes:
        raise NotImplementedError("_decrypt_internal method not implemented")

    @abstractmethod
    def _is_encrypted_internal(self, data: bytes) -> bool:
        raise NotImplementedError("_is_encrypted_internal method not implemented")

    @property
    @abstractmethod
    def prefix(self) -> bytes:
        raise NotImplementedError("prefix property not implemented")

    def _is_legacy_data(self, data: bytes) -> bool:
        # No prefix => legacy Fernet token
        fernet_encryption = FernetEncryption(self.keys)
        return fernet_encryption._is_encrypted_internal(data)

    def encrypt(self, data: bytes) -> bytes:
        if self.encryption_disabled:
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
        if self.encryption_disabled:
            return data

        for prefix, enc_class in self._encryption_registry.items():
            if data.startswith(prefix):
                # Found prefix, use that crypter only
                crypter = enc_class(self.keys)
                without_prefix = data[len(prefix):]
                if prefix == FERNET_PREFIX:
                    # Fernet token directly
                    return crypter._decrypt_internal(without_prefix)
                else:
                    # AES: urlsafe_b64decode
                    raw_encrypted = base64.urlsafe_b64decode(without_prefix)
                    return crypter._decrypt_internal(raw_encrypted)

        # No prefix => legacy Fernet
        if self._is_legacy_data(data):
            fernet_encryption = FernetEncryption(self.keys)
            return fernet_encryption._decrypt_legacy(data)

        raise ValueError("Invalid prefix for encrypted data")

    def _decrypt_legacy(self, data: bytes) -> bytes:
        fernet_encryption = FernetEncryption(self.keys)
        return fernet_encryption._decrypt_legacy(data)

    def is_encrypted(self, data: Union[str, bytes]) -> bool:
        if isinstance(data, str):
            data = data.encode("utf-8")


        for prefix, enc_class in self._encryption_registry.items():
            if data.startswith(prefix):
                crypter = enc_class(self.keys)
                without_prefix = data[len(prefix):]
                if prefix == FERNET_PREFIX:
                    # Fernet token directly
                    return crypter._is_encrypted_internal(without_prefix)
                else:
                    # AES: urlsafe_b64decode and check
                    try:
                        raw_encrypted = base64.urlsafe_b64decode(without_prefix)
                        return crypter._is_encrypted_internal(raw_encrypted)
                    except Exception:
                        return False

        # No prefix => legacy Fernet
        return self._is_legacy_data(data)

    def encrypt_str(self, s: str) -> str:
        if self.encryption_disabled or self.is_encrypted(s.encode("utf-8")):
            return s
        encrypted = self.encrypt(s.encode("utf-8"))
        return encrypted.decode("utf-8")

    def decrypt_str(self, value: str) -> str:
        if self.encryption_disabled:
            return value

        decrypted = self.decrypt(value.encode("utf-8"))
        return decrypted.decode("utf-8")

    def encrypt_values(self, data, json_skip_keys=None, encoder=None):
        if self.encryption_disabled:
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
        if self.encryption_disabled:
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
            return literal_eval(decrypted_data)
        except (ValueError, SyntaxError):
            return self.decoder.decode(decrypted_data)


class FernetEncryption(EncryptionMethod):
    prefix = FERNET_PREFIX

    def __init__(self, keys):
        super().__init__(keys)
        try:
            self.crypter = MultiFernet([Fernet(key) for key in keys])
        except Exception as e:
            raise ValueError(f"Invalid Fernet key: {e}")

    def _encrypt_raw(self, data: bytes) -> bytes:
        # Returns Fernet token directly (URL-safe base64)
        return self.crypter.encrypt(data)

    def _decrypt_internal(self, data: bytes) -> bytes:
        # data is Fernet token directly
        return self.crypter.decrypt(data)

    def _is_encrypted_internal(self, data: bytes) -> bool:
        try:
            self.crypter.decrypt(data, ttl=None)
            return True
        except InvalidToken:
            return False

    def _decrypt_legacy(self, data: bytes) -> bytes:
        # legacy Fernet
        return self.crypter.decrypt(data)

    def _final_encrypt(self, data: bytes) -> bytes:
        # For Fernet: _encrypt_raw returns token, just prefix + token
        raw_encrypted = self._encrypt_raw(data)
        # No extra encoding needed
        return self.prefix + raw_encrypted


class AESEncryption(EncryptionMethod):
    prefix = AES_PREFIX

    def __init__(self, keys):
        super().__init__(keys)
        self.crypter = MultiAES(keys)

    def _encrypt_raw(self, data: bytes) -> bytes:
        # AES: raw binary
        return self.crypter.encrypt(data)

    def _decrypt_internal(self, data: bytes) -> bytes:
        # data is raw binary after decode
        return self.crypter.decrypt(data)

    def _is_encrypted_internal(self, data: bytes) -> bool:
        try:
            self.crypter.decrypt(data)
            return True
        except Exception:
            return False

    def _final_encrypt(self, data: bytes) -> bytes:
        # For AES: raw_encrypted is binary, urlsafe_b64encode then prefix
        raw_encrypted = self._encrypt_raw(data)
        encoded = base64.urlsafe_b64encode(raw_encrypted)
        return self.prefix + encoded


EncryptionMethod.register_encryption_method(AES_PREFIX, AESEncryption)
EncryptionMethod.register_encryption_method(FERNET_PREFIX, FernetEncryption)
