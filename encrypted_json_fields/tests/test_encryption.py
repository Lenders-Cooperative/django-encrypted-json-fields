import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from encrypted_json_fields.constants import EncryptionTypes
from encrypted_json_fields.encryption import (
    AESCBCEncryption,
    AESGCMEncryption,
    FernetEncryption,
)


class EncryptionTests(TestCase):
    def setUp(self):
        self.fernet_keys = [os.urandom(32)]  # Valid Fernet keys
        self.aes_keys = [os.urandom(32)]
        self.keys = {"aes": self.aes_keys, "fernet": self.fernet_keys}
        self.fernet_encryption = FernetEncryption(self.keys)
        self.aes_encryption = AESCBCEncryption(self.keys)

    def test_encrypt_decrypt_fernet(self):
        data = b"test data"
        encrypted = self.fernet_encryption.encrypt(data)  # prefix + no double Base64 needed
        self.assertNotEqual(encrypted, data)
        self.assertTrue(encrypted.startswith(b"fernet:"))
        decrypted = self.fernet_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

    def test_encrypt_decrypt_aes(self):
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)  # prefix + base64
        self.assertNotEqual(encrypted, data)
        self.assertTrue(encrypted.startswith(b"aes:"))
        decrypted = self.aes_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

    def test_decryption_with_invalid_key_fails(self):
        data = b"test data"
        encrypted = self.fernet_encryption.encrypt(data)
        fernet_encryption = FernetEncryption({"aes": self.aes_keys, "fernet": [os.urandom(32)]})
        with self.assertRaises(InvalidToken) as context:
            fernet_encryption.decrypt(encrypted)
        self.assertIsInstance(context.exception, InvalidToken)

    def test_decryption_with_invalid_key_fails_aes(self):
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)
        aes_encryption = AESCBCEncryption({"aes": [os.urandom(32)], "fernet": self.fernet_keys})
        with self.assertRaises(ValueError):
            aes_encryption.decrypt(encrypted)

    def test_encryption_disabled_does_not_encrypt_fernet(self):
        self.fernet_encryption.encryption_enabled = False
        data = b"test data"
        encrypted = self.fernet_encryption.encrypt(data)
        # If disabled, 'encrypt' returns original data as is
        self.assertEqual(encrypted, data)

    def test_encryption_disabled_does_not_encrypt_aes(self):
        self.aes_encryption.encryption_enabled = False
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)
        self.assertEqual(encrypted, data)

    def test_aes_invalid_key_length(self):
        invalid_aes_keys = [os.urandom(16)]  # Use 16 bytes instead of 32
        keys = {"aes": invalid_aes_keys, "fernet": self.fernet_keys}
        with self.assertRaises(ValueError):
            AESCBCEncryption(keys)

    def test_is_encrypted_internal_fernet(self):
        data = b"test data"

        # Test with prefixed data (Fernet no extra base64)
        encrypted_prefixed = self.fernet_encryption.encrypt(data)
        self.assertTrue(self.fernet_encryption.is_encrypted(encrypted_prefixed))

        # Test with legacy data: raw Fernet encryption without prefix
        raw_fernet = Fernet(base64.urlsafe_b64encode(self.fernet_keys[0]))
        encrypted_legacy = raw_fernet.encrypt(data)  # legacy fernet token
        # Should also be recognized as encrypted
        self.assertTrue(self.fernet_encryption.is_encrypted(encrypted_legacy))

        # Test with invalid data:
        # Create data that starts with unknown prefix + base64 nonsense
        unknown_prefix = b"UnknownPrefix:"
        # Make some random binary data to encode
        random_data = os.urandom(10)
        base64_data = base64.urlsafe_b64encode(random_data)
        invalid_data = unknown_prefix + base64_data
        # Should return False, not recognized as encrypted
        self.assertFalse(self.fernet_encryption.is_encrypted(invalid_data))

    def test_is_encrypted_internal_aes(self):
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)
        # After decode and prefix check inside is_encrypted, it should confirm
        self.assertTrue(self.aes_encryption.is_encrypted(encrypted))

    def test_decrypt_with_invalid_prefix(self):
        # Create data with unknown prefix and urlsafe base64 random data
        unknown_prefix = b"BadPrefix:"
        random_data = os.urandom(10)
        base64_data = base64.urlsafe_b64encode(random_data)
        invalid_data = unknown_prefix + base64_data

        with self.assertRaises(ValueError) as context:
            self.fernet_encryption.decrypt(invalid_data)
        self.assertEqual(str(context.exception), "Invalid prefix or data format for encrypted data")

    def test_legacy_fernet_decryption(self):
        raw_fernet = Fernet(base64.urlsafe_b64encode(self.fernet_keys[0]))
        data = b"test data"
        encrypted = raw_fernet.encrypt(data)  # Legacy data (just a Fernet token)
        decrypted = self.fernet_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

        # Verify legacy data is recognized as encrypted
        self.assertTrue(self.fernet_encryption.is_encrypted(encrypted))

    def test_global_encryption_disabled(self):
        self.fernet_encryption.encryption_enabled = False
        data = b"test data"
        encrypted = self.fernet_encryption.encrypt(data)
        self.assertEqual(encrypted, data)  # no encryption if disabled
        decrypted = self.fernet_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

    def test_improperly_configured_keys(self):
        # Test with AESCBCEncryption
        with self.assertRaises(ImproperlyConfigured):
            AESCBCEncryption([]).get_crypter_keys()

        # Test with FernetEncryption
        with self.assertRaises(ImproperlyConfigured):
            FernetEncryption([]).get_crypter_keys()

    def test_encrypt_values_recursively(self):
        nested_data = {
            "key1": 123,
            "key2": [True, "nested", {"subkey": 3.14}],
        }
        encrypted = self.fernet_encryption.encrypt_values(nested_data)
        self.assertNotEqual(nested_data, encrypted)
        decrypted = self.fernet_encryption.decrypt_values(encrypted)
        self.assertEqual(decrypted, nested_data)

    def test_decrypt_values_recursively(self):
        nested_data = {
            "key1": 123,
            "key2": [True, "nested", {"subkey": 3.14}],
        }
        encrypted = self.fernet_encryption.encrypt_values(nested_data)
        decrypted = self.fernet_encryption.decrypt_values(encrypted)
        self.assertEqual(decrypted, nested_data)

    def test_encrypt_values_with_skip_keys(self):
        nested_data = {
            "key1": "no_encrypt",
            "key2": {"skip": "leave_me", "encrypt": "this_one"},
        }
        encrypted = self.fernet_encryption.encrypt_values(nested_data, json_skip_keys=["skip"])
        # 'skip' should not be encrypted
        self.assertEqual(encrypted["key2"]["skip"], "leave_me")
        self.assertNotEqual(encrypted["key2"]["encrypt"], "this_one")

    def test_aes_decrypt_fails_with_corrupted_data(self):
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)
        corrupted = encrypted[:10] + b"corruption" + encrypted[10:]
        with self.assertRaises(ValueError):
            self.aes_encryption.decrypt(corrupted)


class AESGCMEncryptionTests(TestCase):
    def setUp(self):
        self.aes_gcm_encryption = AESGCMEncryption({EncryptionTypes.AES_GCM.value: [os.urandom(32)]})

    def test_aes_gcm_encrypt_decrypt(self):
        data = b"test data"
        encrypted = self.aes_gcm_encryption.encrypt(data)
        self.assertNotEqual(encrypted, data)
        self.assertTrue(encrypted.startswith(b"aes_gcm:"))
        decrypted = self.aes_gcm_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

    def test_aes_gcm_decryption_with_invalid_key_fails(self):
        data = b"test data"
        encrypted = self.aes_gcm_encryption.encrypt(data)
        aes_gcm_encryption = AESGCMEncryption({EncryptionTypes.AES_GCM.value: [os.urandom(32)]})
        with self.assertRaises(ValueError) as context:
            aes_gcm_encryption.decrypt(encrypted)
        self.assertIsInstance(context.exception, ValueError)

    def test_aes_gcm_encryption_disabled_does_not_encrypt(self):
        self.aes_gcm_encryption.encryption_enabled = False
        data = b"test data"
        encrypted = self.aes_gcm_encryption.encrypt(data)
        self.assertEqual(encrypted, data)

    def test_aes_gcm_invalid_key_length(self):
        invalid_aes_keys = [os.urandom(16)]  # Use 16 bytes instead of 32
        with self.assertRaises(ValueError) as context:
            AESGCMEncryption({EncryptionTypes.AES_GCM.value: invalid_aes_keys})
        self.assertIn("All AES keys must be 256 bits (32 bytes).", str(context.exception))

    def test_aes_gcm_decrypt_fails_with_corrupted_data(self):
        data = b"test data"
        encrypted = self.aes_gcm_encryption.encrypt(data)
        non_ciphertext_data_length = len(EncryptionTypes.AES_GCM.value) + 1 + 12
        corrupted = encrypted[:non_ciphertext_data_length] + b"corruption" + encrypted[non_ciphertext_data_length:]
        with self.assertRaises(ValueError) as context:
            self.aes_gcm_encryption.decrypt(corrupted)
        self.assertIsInstance(context.exception, ValueError)
