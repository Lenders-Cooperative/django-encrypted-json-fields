import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from encrypted_json_fields.encryption import (
    MultiAES,
    EncryptionMethod,
    FernetEncryption,
    AESEncryption,
)


class EncryptionTests(TestCase):
    def setUp(self):
        self.keys = [Fernet.generate_key()]  # Valid Fernet keys
        self.aes_keys = [os.urandom(32)]     # Valid AES keys
        self.fernet_encryption = FernetEncryption(self.keys)
        self.aes_encryption = AESEncryption(self.aes_keys)

    def test_encrypt_decrypt_fernet(self):
        data = b"test data"
        encrypted = self.fernet_encryption.encrypt(data)  # prefix + no double Base64 needed
        decrypted = self.fernet_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

    def test_encrypt_decrypt_aes(self):
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)  # prefix + base64
        decrypted = self.aes_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

    def test_decryption_with_invalid_key_fails(self):
        data = b"test data"
        encrypted = self.fernet_encryption.encrypt(data)
        self.fernet_encryption.keys = [Fernet.generate_key()]  # Replace keys
        with self.assertRaises(InvalidToken) as context:
            self.fernet_encryption.decrypt(encrypted)
        self.assertIsInstance(context.exception, InvalidToken)

    def test_decryption_with_invalid_key_fails_aes(self):
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)
        self.aes_encryption.keys = [os.urandom(32)]  # Replace keys
        with self.assertRaises(ValueError):
            self.aes_encryption.decrypt(encrypted)

    def test_encryption_disabled_does_not_encrypt_fernet(self):
        self.fernet_encryption.encryption_disabled = True
        data = b"test data"
        encrypted = self.fernet_encryption.encrypt(data)
        # If disabled, 'encrypt' returns original data as is
        self.assertEqual(encrypted, data)

    def test_encryption_disabled_does_not_encrypt_aes(self):
        self.aes_encryption.encryption_disabled = True
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)
        self.assertEqual(encrypted, data)

    def test_aes_invalid_key_length(self):
        invalid_keys = [os.urandom(16)]  # Use 16 bytes instead of 32
        with self.assertRaises(ValueError):
            AESEncryption(invalid_keys)

    def test_is_encrypted_internal_fernet(self):
        data = b"test data"

        # Test with prefixed data (Fernet no extra base64)
        encrypted_prefixed = self.fernet_encryption.encrypt(data)
        self.assertTrue(self.fernet_encryption.is_encrypted(encrypted_prefixed))

        # Test with legacy data: raw Fernet encryption without prefix
        raw_fernet = Fernet(self.keys[0])
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
        self.assertEqual(str(context.exception),
                         "Invalid prefix for encrypted data")

    def test_legacy_fernet_decryption(self):
        raw_fernet = Fernet(self.keys[0])
        data = b"test data"
        encrypted = raw_fernet.encrypt(data)  # Legacy data (just a Fernet token)
        decrypted = self.fernet_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

        # Verify legacy data is recognized as encrypted
        self.assertTrue(self.fernet_encryption.is_encrypted(encrypted))

    def test_global_encryption_disabled(self):
        self.fernet_encryption.encryption_disabled = True
        data = b"test data"
        encrypted = self.fernet_encryption.encrypt(data)
        self.assertEqual(encrypted, data)  # no encryption if disabled
        decrypted = self.fernet_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, data)

    def test_improperly_configured_keys(self):
        # Test with AESEncryption
        with self.assertRaises(ImproperlyConfigured):
            AESEncryption([]).get_crypter_keys()

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
        encrypted = self.fernet_encryption.encrypt_values(
            nested_data, json_skip_keys=["skip"]
        )
        # 'skip' should not be encrypted
        self.assertEqual(encrypted["key2"]["skip"], "leave_me")
        self.assertNotEqual(encrypted["key2"]["encrypt"], "this_one")

    def test_aes_decrypt_fails_with_corrupted_data(self):
        data = b"test data"
        encrypted = self.aes_encryption.encrypt(data)
        corrupted = encrypted[:10] + b"corruption" + encrypted[10:]
        with self.assertRaises(ValueError):
            self.aes_encryption.decrypt(corrupted)
