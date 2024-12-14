import pytest
from django.db import models
from encrypted_json_fields.encryption import FernetEncryption, AESEncryption
from encrypted_json_fields.fields import (
    EncryptedCharField,
    EncryptedTextField,
    EncryptedDateTimeField,
    EncryptedEmailField,
    EncryptedBooleanField,
    EncryptedJSONField,
)

# Test model for encrypted fields
class TestModel(models.Model):
    char_field = EncryptedCharField(max_length=255, crypter=None)
    text_field = EncryptedTextField(crypter=None)
    datetime_field = EncryptedDateTimeField(crypter=None)
    email_field = EncryptedEmailField(crypter=None)
    boolean_field = EncryptedBooleanField(crypter=None)
    json_field = EncryptedJSONField(crypter=None)

@pytest.fixture(scope="module")
def fernet_keys():
    return ["fernet_key_1", "fernet_key_2"]

@pytest.fixture(scope="module")
def aes_keys():
    return ["aes_key_1", "aes_key_2"]

@pytest.fixture
def fernet_instance(fernet_keys):
    return TestModel(
        char_field=EncryptedCharField(max_length=255, crypter=FernetEncryption(keys=fernet_keys)),
        text_field=EncryptedTextField(crypter=FernetEncryption(keys=fernet_keys)),
        datetime_field=EncryptedDateTimeField(crypter=FernetEncryption(keys=fernet_keys)),
        email_field=EncryptedEmailField(crypter=FernetEncryption(keys=fernet_keys)),
        boolean_field=EncryptedBooleanField(crypter=FernetEncryption(keys=fernet_keys)),
        json_field=EncryptedJSONField(crypter=FernetEncryption(keys=fernet_keys)),
    )

@pytest.fixture
def aes_instance(aes_keys):
    return TestModel(
        char_field=EncryptedCharField(max_length=255, crypter=AESEncryption(keys=aes_keys)),
        text_field=EncryptedTextField(crypter=AESEncryption(keys=aes_keys)),
        datetime_field=EncryptedDateTimeField(crypter=AESEncryption(keys=aes_keys)),
        email_field=EncryptedEmailField(crypter=AESEncryption(keys=aes_keys)),
        boolean_field=EncryptedBooleanField(crypter=AESEncryption(keys=aes_keys)),
        json_field=EncryptedJSONField(crypter=AESEncryption(keys=aes_keys)),
    )

def test_encryption_and_decryption(fernet_instance):
    """Test that fields are encrypted and decrypted correctly for Fernet."""
    # Save the instance
    fernet_instance.save()

    # Assert encrypted value is not plaintext
    reloaded_instance = TestModel.objects.get(id=fernet_instance.id)
    assert reloaded_instance.char_field == fernet_instance.char_field
    assert reloaded_instance.text_field == fernet_instance.text_field

def test_encryption_and_decryption_aes(aes_instance):
    """Test that fields are encrypted and decrypted correctly for AES."""
    # Save the instance
    aes_instance.save()

    # Assert encrypted value is not plaintext
    reloaded_instance = TestModel.objects.get(id=aes_instance.id)
    assert reloaded_instance.char_field == aes_instance.char_field
    assert reloaded_instance.text_field == aes_instance.text_field

def test_boolean_field_encryption(fernet_instance):
    """Test that boolean fields are encrypted and decrypted correctly for Fernet."""
    fernet_instance.boolean_field = False
    fernet_instance.save()

    reloaded_instance = TestModel.objects.get(id=fernet_instance.id)
    assert reloaded_instance.boolean_field is False

def test_json_field_encryption(fernet_instance):
    """Test that JSON fields are encrypted and decrypted correctly for Fernet."""
    fernet_instance.json_field = {"nested": {"key": "another_value"}}
    fernet_instance.save()

    reloaded_instance = TestModel.objects.get(id=fernet_instance.id)
    assert reloaded_instance.json_field == {"nested": {"key": "another_value"}}

def test_field_validation():
    """Test validation on encrypted fields."""
    invalid_instance = TestModel(char_field=None)

    with pytest.raises(ValueError):
        invalid_instance.full_clean()
