import os
from cryptography.fernet import Fernet
from django.test import TestCase, override_settings
from encrypted_json_fields.encryption import AESEncryption, FernetEncryption
from encrypted_json_fields.helpers import get_default_crypter


class GetDefaultCrypterTest(TestCase):
    def setUp(self):
        # Mock encryption keys
        self.keys = {
            "aes": [os.urandom(32)],
            "fernet": [Fernet.generate_key()]
        }

    @override_settings(EJF_DEFAULT_ENCRYPTION="aes")
    def test_get_default_crypter_aes(self):
        """Test that the default crypter returns an AESEncryption instance."""
        crypter = get_default_crypter(self.keys)
        self.assertIsInstance(crypter, AESEncryption)
        self.assertEqual(crypter.keys, self.keys)  # Ensure keys are passed correctly

    @override_settings(EJF_DEFAULT_ENCRYPTION="fernet")
    def test_get_default_crypter_fernet(self):
        """Test that the default crypter returns a FernetEncryption instance."""
        crypter = get_default_crypter(self.keys)
        self.assertIsInstance(crypter, FernetEncryption)
        self.assertEqual(crypter.keys, self.keys)  # Ensure keys are passed correctly

    @override_settings(EJF_DEFAULT_ENCRYPTION="FerneT")
    def test_get_default_crypter_case_insentive(self):
        """Test that the default crypter returns a FernetEncryption instance."""
        crypter = get_default_crypter(self.keys)
        self.assertIsInstance(crypter, FernetEncryption)
        self.assertEqual(crypter.keys, self.keys)  # Ensure keys are passed correctly

    @override_settings(EJF_DEFAULT_ENCRYPTION="nonexistentencryption")
    def test_get_default_crypter_invalid_setting(self):
        """Test that an invalid EJF_DEFAULT_ENCRYPTION setting raises an error."""
        with self.assertRaises(ValueError) as context:
            get_default_crypter(self.keys)
        self.assertIn("Encryption method 'nonexistentencryption' is not a registered encryption class.", str(context.exception))

    @override_settings(EJF_DEFAULT_ENCRYPTION=None)
    def test_get_default_crypter_missing_setting(self):
        """Test that a missing EJF_DEFAULT_ENCRYPTION setting raises an error."""
        with self.assertRaises(ValueError) as context:
            get_default_crypter(self.keys)
        self.assertIn("EJF_DEFAULT_ENCRYPTION setting is not defined", str(context.exception))
