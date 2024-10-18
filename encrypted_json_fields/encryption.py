from abc import ABC, abstractmethod
import json
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import Union
import base64
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os
from ast import literal_eval


class MultiAES:
    def __init__(self, keys):
        """ Initialize with multiple keys """
        self.keys = keys  # List of keys

    def encrypt(self, plaintext):
        """ Encrypt with the latest key """
        key = self.keys[-1]  # Use the latest key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding for block size
        padding_length = 16 - len(plaintext) % 16
        padded_data = plaintext + bytes([padding_length]) * padding_length

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Create HMAC for authentication
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        hmac_tag = h.finalize()

        return iv + ciphertext + hmac_tag

    def decrypt(self, ciphertext):
        """ Try to decrypt with any available key """
        for key in self.keys:
            try:
                iv = ciphertext[:16]
                cipher_text_only = ciphertext[16:-32]
                hmac_tag = ciphertext[-32:]

                # Verify HMAC
                h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
                h.update(iv + cipher_text_only)
                h.verify(hmac_tag)

                # If HMAC is correct, decrypt
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(cipher_text_only)
                decrypted_data += decryptor.finalize()

                # Remove padding
                padding_length = decrypted_data[-1]
                return decrypted_data[:-padding_length]
            except Exception:
                pass  # Try next key if this one fails
        raise ValueError("Decryption failed with all keys")


class EncryptionMethod(ABC):
    def __init__(self, encoder=None, decoder=None, force=False):
        self.keys = self.get_crypter_keys()
        self.encoder = encoder or json.JSONEncoder()
        self.decoder = decoder or json.JSONDecoder()
        self.force = force
        self.crypter = self.build_crypter()
        self.encryption_disabled = force or getattr(
            settings,
            "EJF_DISABLE_ENCRYPTION",
            False
        )

    def build_crypter(self):
        """
        Build a crypter for the configured keys (as specified in projects's settings)
        """
        raise NotImplementedError("build_crypter method not implemented")

    def get_crypter_keys(self):
        """
        Retrieve the configured keys for the crypter
        """
        configured_keys = getattr(settings, "EJF_ENCRYPTION_KEYS", None)
        if callable(configured_keys):
            configured_keys = configured_keys()

        if not configured_keys:
            raise ImproperlyConfigured("EJF_ENCRYPTION_KEYS must be defined in settings")

        if not isinstance(configured_keys, (list, tuple)):
            configured_keys = [configured_keys]  

        return configured_keys

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt the given data
        """
        raise NotImplementedError("encrypt method not implemented")

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt the given data
        """
        raise NotImplementedError("decrypt method not implemented")

    @abstractmethod
    def is_encrypted(self, s: Union[str, bytes]) -> bool:
        """
        Check if the given string (or bytes) is the result of an encryption
        """
        raise NotImplementedError("is_encrypted method not implemented")

    def encrypt_str(self, s: str) -> str:
        """
        Encrypt the given string
        """
        encoded_string = s.encode("utf-8")
        if self.encryption_disabled or self.is_encrypted(encoded_string):
            return encoded_string

        if self.crypter is None:
            self.crypter = self.get_default_crypter()

        return self.encrypt(encoded_string).decode("utf-8")

    def decrypt_bytes(self, s: str) -> str:
        """
        Decrypt the given string
        """
        assert type(s) in [
            bytes,
        ]

        if self.encryption_disabled:
            return s.decode("utf-8")

        try:
            return self.crypter.decrypt(s).decode("utf-8")
        except Exception:
            try:
                return s.decode("utf-8")
            except Exception:
                return str(s)

    def encrypt_values(self, data, json_skip_keys=None, encoder=None):
        """
        Encrypt the given data
        """
        if self.encryption_disabled:
            return data

        # Scan the lists, then decode each item recursively
        if isinstance(data, (list, tuple, set)):
            return [self.encrypt_values(x) for x in data]

        # Scan the dicts, then decode each item recursively
        if isinstance(data, dict):
            return {key: self.encrypt_values(value) for key, value in data.items()}

        # We finally have a simple item to work with, which can be:
        # a string, a number, a boolean, or null.
        # Since we don't want lo lose the item's type, we apply repr()
        # to obtain a printable representational string of it,
        # before proceeding with the encryption

        if encoder is None:
            encoder_obj = json.JSONEncoder()
        else:
            encoder_obj = encoder()

        if isinstance(data, (int, float, bool, str)):
            encoded_data = repr(data)
        else:
            encoded_data = encoder_obj.encode(data)

        encrypted_data = self.encrypt_str(encoded_data)

        # Return the result as string, so that it can be JSON-serialized later
        return encrypted_data.decode("utf-8")

    def decrypt_values(self, data):
        if self.encryption_disabled:
            return data

        # Scan the lists, then decode each item recursively
        if isinstance(data, (list, tuple, set)):
            return [self.decrypt_values(x) for x in data]

        if isinstance(data, dict):
            return {key: self.decrypt_values(value) for key, value in data.items()}

        try:
            if not isinstance(data, str):
                return data

            if not self.is_encrypted(data):
                return data 

            data = self.decrypt_bytes(data.encode("utf-8"))

            try:
                value = literal_eval(data)
            except ValueError:
                value = self.decoder.decode(data)
        except Exception:
            value = str(data)

        return value
    

class FernetEncryption(EncryptionMethod):
    def __init__(self, keys):
        self.crypter = MultiFernet([Fernet(key) for key in keys])

    def encrypt(self, data: bytes) -> bytes:
        return self.crypter.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.crypter.decrypt(data)

    def is_encrypted(self, data: bytes) -> bool:
        result = True
        try:
            token = data.encode("utf-8") if isinstance(data, str) else data
            timestamp, data = self.crypter._get_unverified_token_data(token)
        except InvalidToken:
            result = False

        return result


class AESEncryption(EncryptionMethod):
    def __init__(self, keys):
        self.crypter = MultiAES(keys)

    def encrypt(self, data: bytes) -> bytes:
        return self.crypter.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.crypter.decrypt(data)

    def is_encrypted(self, data: bytes) -> bool:
        try:
            raw = base64.b64decode(data)
            if len(raw) < AES.block_size:
                return False
            cipher = AES.new(self.crypter.keys[-1], AES.MODE_CBC, iv=raw[:AES.block_size])
            cipher.decrypt(raw[AES.block_size:])
            return True
        except (ValueError, KeyError):
            return False
