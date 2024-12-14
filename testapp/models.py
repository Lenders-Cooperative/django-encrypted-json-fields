from django.db import models
from django.core.serializers.json import DjangoJSONEncoder

from encrypted_json_fields.fields import (
    EncryptedCharField,
    EncryptedTextField,
    EncryptedDateField,
    EncryptedDateTimeField,
    EncryptedBooleanField,
    EncryptedIntegerField,
    EncryptedPositiveIntegerField,
    EncryptedSmallIntegerField,
    EncryptedPositiveSmallIntegerField,
    EncryptedBigIntegerField,
    EncryptedJSONField,
    EncryptedSearchField,
)

class CrypterConfigMixin:
    """Mixin to dynamically set crypter and keys."""
    crypter_class = None
    crypter_keys = []

    @classmethod
    def set_crypter(cls, crypter_class, keys):
        cls.crypter_class = crypter_class
        cls.crypter_keys = keys

    @classmethod
    def get_crypter(cls):
        if cls.crypter_class is None or not cls.crypter_keys:
            raise ValueError("Crypter class and keys must be set before use.")
        return cls.crypter_class(keys=cls.crypter_keys)


class TestModel(CrypterConfigMixin, models.Model):
    enc_char_field = EncryptedCharField(max_length=100, crypter=CrypterConfigMixin.get_crypter)
    enc_text_field = EncryptedTextField(crypter=CrypterConfigMixin.get_crypter)
    enc_date_field = EncryptedDateField(null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_date_now_field = EncryptedDateField(auto_now=True, null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_date_now_add_field = EncryptedDateField(auto_now_add=True, null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_datetime_field = EncryptedDateTimeField(null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_boolean_field = EncryptedBooleanField(default=True, crypter=CrypterConfigMixin.get_crypter)
    enc_integer_field = EncryptedIntegerField(null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_positive_integer_field = EncryptedPositiveIntegerField(null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_small_integer_field = EncryptedSmallIntegerField(null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_positive_small_integer_field = EncryptedPositiveSmallIntegerField(null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_big_integer_field = EncryptedBigIntegerField(null=True, crypter=CrypterConfigMixin.get_crypter)
    enc_json_field = EncryptedJSONField(
        null=False, blank=True, default=dict, encoder=DjangoJSONEncoder, crypter=CrypterConfigMixin.get_crypter
    )


class TestSearchableModel(CrypterConfigMixin, models.Model):
    enc_char_field = EncryptedCharField(max_length=100, crypter=CrypterConfigMixin.get_crypter)
    char_field = EncryptedSearchField(salt="1234", encrypted_field_name="enc_char_field")

    enc_date_field = EncryptedDateField(null=True, crypter=CrypterConfigMixin.get_crypter)
    date_field = EncryptedSearchField(salt="xyz", encrypted_field_name="enc_date_field")

    enc_integer_field = EncryptedIntegerField(null=True, crypter=CrypterConfigMixin.get_crypter)
    integer_field = EncryptedSearchField(encrypted_field_name="enc_integer_field")
