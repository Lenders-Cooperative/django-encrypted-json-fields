from django.apps import AppConfig
from cryptography.fernet import Fernet

class TestAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "testapp"

    @staticmethod
    def generate_fernet_keys(key_count=2):
        """Generate a list of valid Fernet keys."""
        return [Fernet.generate_key().decode("utf-8") for _ in range(key_count)]

    def ready(self):
        # Import models to avoid circular imports
        from .models import TestModel, TestSearchableModel
        from encrypted_json_fields.encryption import FernetEncryption

        # Generate Fernet keys dynamically
        fernet_keys = self.generate_fernet_keys()

        # Set the crypter for runtime usage
        TestModel.set_crypter(FernetEncryption, fernet_keys)
        TestSearchableModel.set_crypter(FernetEncryption, fernet_keys)
