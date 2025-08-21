import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from encrypted_json_fields.constants import EncryptionTypes
from encrypted_json_fields.encryption import EncryptionInterface, FernetEncryption


class EncryptionTests(TestCase):
    def setUp(self):
        self.fernet_encryption = FernetEncryption({EncryptionTypes.FERNET.value: [os.urandom(32)]})

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

    def test_data_type_preservation(self):
        test_cases = [
            ("string", "test string"),
            ("integer", 123),
            ("integer_string", "523"),
            ("float", 3.14),
            ("float_string", "5.14"),
            ("boolean_true", True),
            ("boolean_false", False),
            ("none", None),
        ]

        for data_type, value in test_cases:
            with self.subTest(data_type=data_type):
                encrypted = self.fernet_encryption.encrypt_values(value)
                decrypted = self.fernet_encryption.decrypt_values(encrypted)

                self.assertEqual(decrypted, value)
                self.assertEqual(type(decrypted), type(value))

    def test_fernet_prefix_respected(self):
        cases = ((False, "no_prefix"), (True, "with_prefix"))
        for enabled, name in cases:
            with self.subTest(case=name, prefix_enabled=enabled):
                with override_settings(SECURITY_SETTINGS={"PREFIX_FERNET_ALGO": enabled}):
                    data = b"test data"
                    encrypted = self.fernet_encryption.encrypt(data)
                    if enabled:
                        self.assertTrue(encrypted.startswith(b"fernet:"))
                    else:
                        self.assertFalse(encrypted.startswith(b"fernet:"))


class EncryptionInterfaceTests(TestCase):
    def setUp(self):
        self.keys = {enc_type.value: [os.urandom(32)] for enc_type in EncryptionTypes}
        self.enc_interface_items = EncryptionInterface.get_encryption_registry().items()

    def test_improperly_configured_keys(self):
        for enc_type, enc_interface in self.enc_interface_items:
            with self.subTest(encryption_type=enc_type):
                with self.assertRaises(ImproperlyConfigured):
                    enc_interface([])

    def test_encrypt_decrypt(self):
        for enc_type, enc_interface in self.enc_interface_items:
            with self.subTest(encryption_type=enc_type):
                data = b"test data"
                crypter = enc_interface(self.keys)
                encrypted = crypter.encrypt(data)
                self.assertNotEqual(encrypted, data)
                self.assertTrue(encrypted.startswith(f"{enc_type}:".encode()))
                decrypted = crypter.decrypt(encrypted)
                self.assertEqual(decrypted, data)

    def test_decrypt_with_invalid_prefix(self):
        for enc_type, enc_interface in self.enc_interface_items:
            with self.subTest(encryption_type=enc_type):
                # Create data with unknown prefix and urlsafe base64 random data
                unknown_prefix = b"BadPrefix:"
                random_base64_data = base64.urlsafe_b64encode(os.urandom(10))
                invalid_data = unknown_prefix + random_base64_data

                with self.assertRaises(ValueError) as context:
                    crypter = enc_interface(self.keys)
                    crypter.decrypt(invalid_data)
                self.assertEqual(str(context.exception), "Invalid prefix or data format for encrypted data.")

    def test_decryption_with_invalid_key_fails(self):
        for enc_type, enc_interface in self.enc_interface_items:
            with self.subTest(encryption_type=enc_type):
                data = b"test data"
                crypter = enc_interface(self.keys)
                encrypted = crypter.encrypt(data)
                rekeyed_crypter = enc_interface({enc_type: [os.urandom(32)]})
                with self.assertRaises((InvalidToken, ValueError)) as context:
                    rekeyed_crypter.decrypt(encrypted)
                self.assertIsInstance(context.exception, (InvalidToken, ValueError))

    def test_encryption_disabled_does_not_encrypt(self):
        for enc_type, enc_interface in self.enc_interface_items:
            with self.subTest(encryption_type=enc_type):
                data = b"test data"
                crypter = enc_interface(self.keys)
                crypter.encryption_enabled = False
                encrypted = crypter.encrypt(data)
                self.assertEqual(encrypted, data)

    def test_invalid_key_length(self):
        for enc_type, enc_interface in self.enc_interface_items:
            with self.subTest(encryption_type=enc_type):
                invalid_key = [os.urandom(16)]  # Use 16 bytes instead of 32
                with self.assertRaises(ValueError) as context:
                    enc_interface({enc_type: invalid_key})
                self.assertIn("32", str(context.exception))

    def test_decrypt_fails_with_corrupted_data(self):
        for enc_type, enc_interface in self.enc_interface_items:
            with self.subTest(encryption_type=enc_type):
                data = b"test data"
                crypter = enc_interface(self.keys)
                encrypted = crypter.encrypt(data)
                non_ciphertext_data_length = len(enc_type) + 1 + 12
                corrupted = (
                    encrypted[:non_ciphertext_data_length] + b"corruption" + encrypted[non_ciphertext_data_length:]
                )
                with self.assertRaises((InvalidToken, ValueError)) as context:
                    crypter.decrypt(corrupted)
                self.assertIsInstance(context.exception, (InvalidToken, ValueError))

    def test_is_encrypted(self):
        for enc_type, enc_interface in self.enc_interface_items:
            with self.subTest(encryption_type=enc_type):
                data = b"test data"
                crypter = enc_interface(self.keys)

                # Test with prefixed data
                encrypted = crypter.encrypt(data)
                self.assertTrue(crypter.is_encrypted(encrypted))

                # Test with legacy data: raw Fernet encryption without prefix
                raw_fernet = Fernet(base64.urlsafe_b64encode(self.keys[EncryptionTypes.FERNET.value][0]))
                encrypted_legacy = raw_fernet.encrypt(data)  # legacy fernet token
                self.assertTrue(crypter.is_encrypted(encrypted_legacy))  # Should also be recognized as encrypted

                # Test with invalid data: data that starts with unknown prefix + base64 nonsense
                unknown_prefix = b"UnknownPrefix:"
                random_data = os.urandom(10)  # Make some random binary data to encode
                base64_data = base64.urlsafe_b64encode(random_data)
                invalid_data = unknown_prefix + base64_data
                self.assertFalse(crypter.is_encrypted(invalid_data))  # Should return False, not recognized as encrypted
