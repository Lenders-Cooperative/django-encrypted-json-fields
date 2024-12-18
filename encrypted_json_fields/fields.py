import hashlib
import itertools
import json
import string
import datetime

import cryptography.fernet
import django.db
import django.db.models
from django.conf import settings
from django.core import validators
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import connection, models
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.text import capfirst

from .encryption import EncryptionMethod, FernetEncryption, AESEncryption


def fetch_raw_field_value(model_instance, fieldname):
    """
    Fetch the field value bypassing Django model,
    thus skipping any decryption
    """

    if connection.vendor in [
        "sqlite",
    ]:
        if type(model_instance.id) == int:
            id_filter = str(model_instance.id)
        else:
            id_filter = '"%s"' % str(model_instance.id).replace("-", "")
        sql = "select %s from %s_%s where id=%s" % (
            fieldname,
            model_instance._meta.app_label,
            model_instance._meta.model_name,
            id_filter,
        )
        params = None
    else:
        # i.e. 'postgresql'
        sql = "select %s from %s_%s where id=%%s" % (
            fieldname,
            model_instance._meta.app_label,
            model_instance._meta.model_name,
        )
        params = (model_instance.id,)

    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()

    return row[0]


class EncryptedMixin(object):
    def __init__(self, crypter=None, *args, **kwargs):
        self._crypter = crypter  # Store the crypter or defer its initialization
        super().__init__(*args, **kwargs)

    @property
    def crypter(self):
        if not self._crypter:
            raise ValueError(
                "Crypter must be set before encryption or decryption.")
        if callable(self._crypter):
            return self._crypter()
        return self._crypter

    @property
    def encryption_enabled(self):
        return (self.crypter.encryption_enabled if self.crypter else True)


    def to_python(self, value):
        if value is None:
            return value
        if isinstance(value, (bytes, str)) and self.crypter.is_encrypted(value):

            try:
                value = self.crypter.decrypt_str(value)
            except Exception as excp:
                print(str(excp))

        return super(EncryptedMixin, self).to_python(value)

    def from_db_value(self, value, *args, **kwargs):
        return self.to_python(value)

    def get_db_prep_save(self, value, connection):
        if value is None:
            return value

        value_type = type(value).__name__
        if value_type in ('datetime', 'date'):
            value = value.isoformat()
        else:
            value = str(value)

        return self.crypter.encrypt_str(value)

    def get_internal_type(self):
        return "TextField"

    def deconstruct(self):
        """
        Ensure crypter is excluded during migrations to prevent serialization issues.
        """
        name, path, args, kwargs = super().deconstruct()
        kwargs.pop("crypter", None)  # Remove the crypter reference for migration safety
        return name, path, args, kwargs

    def validate_max_length(self, value):
        if value is not None and hasattr(self,
                                         'max_length') and self.max_length:
            encrypted_value = self.crypter.encrypt_str(str(value))
            if len(encrypted_value) > self.max_length:
                raise ValidationError(
                    f'Encrypted value would exceed max_length of {self.max_length}'
                )


class EncryptedCharField(EncryptedMixin, django.db.models.CharField):

    def clean(self, value, model_instance):
        value = super().clean(value, model_instance)
        if value is not None and len(value) > self.max_length:
            raise ValidationError(
                f'Value too long (max length is {self.max_length})')
        return value


class EncryptedTextField(EncryptedMixin, django.db.models.TextField):
    pass


class EncryptedDateField(EncryptedMixin, django.db.models.DateField):
    def pre_save(self, model_instance, add):
        if self.auto_now or (add and self.auto_now_add):
            from django.utils import timezone
            value = timezone.now().date()
            setattr(model_instance, self.attname, value)
            return value
        return super().pre_save(model_instance, add)

    def get_db_prep_value(self, value, connection, prepared=False):
        if self.auto_now or (not prepared and self.auto_now_add):
            from django.utils import timezone
            value = timezone.now().date()
        return super().get_db_prep_value(value, connection, prepared)


class EncryptedDateTimeField(EncryptedMixin, django.db.models.DateTimeField):
    # credit to Oleg Pesok...
    def to_python(self, value):
        value = super(EncryptedDateTimeField, self).to_python(value)

        if value is not None and settings.USE_TZ and timezone.is_naive(value):
            default_timezone = timezone.get_default_timezone()
            value = timezone.make_aware(value, default_timezone)

        return value


class EncryptedEmailField(EncryptedMixin, django.db.models.EmailField):
    pass


class EncryptedBooleanField(EncryptedMixin, django.db.models.BooleanField):
    def get_db_prep_save(self, value, connection):
        if value is None:
            return value
        value = "1" if value else "0"
        return self.crypter.encrypt_str(value)

    def from_db_value(self, value, *args, **kwargs):
        if value is None:
            return value
        try:
            decrypted_value = self.crypter.decrypt_str(value)
            return decrypted_value == "1"
        except Exception:
            return None


class EncryptedNumberMixin(EncryptedMixin):
    max_length = 20

    def get_db_prep_save(self, value, connection):
        if value is not None:
            try:
                value = self.to_python(value)  # Convert to Python number
                self.check_value(value)  # Use check_value instead of validate
            except (TypeError, ValueError) as e:
                raise ValidationError(f"Invalid number format: {e}")
            except ValidationError:
                raise
        # After validation passes, encrypt and save
        return super().get_db_prep_save(value, connection)

    def check_value(self, value):
        """
        Validate the value without requiring a model instance.
        This is used for database-level validation.
        """
        return value

    @cached_property
    def validators(self):
        # These validators can't be added at field initialization time since
        # they're based on values retrieved from `connection`.
        range_validators = []
        internal_type = self.__class__.__name__[9:]
        min_value, max_value = django.db.connection.ops.integer_field_range(internal_type)
        if min_value is not None:
            range_validators.append(validators.MinValueValidator(min_value))
        if max_value is not None:
            range_validators.append(validators.MaxValueValidator(max_value))
        return list(itertools.chain(self.default_validators, self._validators, range_validators))


class EncryptedIntegerField(EncryptedNumberMixin, django.db.models.IntegerField):
    description = (
        "An IntegerField that is encrypted before " "inserting into a database using the python cryptography " "library"
    )
    def check_value(self, value):
        if value is not None:
            min_value, max_value = -2147483648, 2147483647
            if not (min_value <= value <= max_value):
                raise ValidationError(f"Value must be between {min_value} and {max_value}")
        super().check_value(value)

class EncryptedPositiveIntegerField(EncryptedIntegerField, django.db.models.PositiveIntegerField):
    def check_value(self, value):
        if value is not None and value < 0:
            raise ValidationError("Positive integer field cannot be negative.")
        super().check_value(value)


class EncryptedSmallIntegerField(EncryptedNumberMixin, django.db.models.SmallIntegerField):
    def check_value(self, value):
        if value is not None:
            min_value, max_value = -32768, 32767
            if not (min_value <= value <= max_value):
                raise ValidationError(f"Value must be between {min_value} and {max_value}")
        super().check_value(value)


class EncryptedPositiveSmallIntegerField(EncryptedSmallIntegerField, django.db.models.PositiveSmallIntegerField):
    def check_value(self, value):
        if value is not None and value < 0:
            raise ValidationError("Positive integer field cannot be negative.")
        super().check_value(value)


class EncryptedBigIntegerField(EncryptedNumberMixin, django.db.models.BigIntegerField):
    def check_value(self, value):
        if value is not None:
            min_value, max_value = -9223372036854775808, 9223372036854775807
            if not (min_value <= value <= max_value):
                raise ValidationError(f"Value must be between {min_value} and {max_value}")
        super().check_value(value)


#################################################################################
# Encryption for JSONField

class EncryptedJSONField(EncryptedMixin, django.db.models.JSONField):
    def __init__(self, crypter=None, *args, **kwargs):
        self.skip_keys = kwargs.pop("skip_keys", [])
        if not isinstance(self.skip_keys, (list, tuple)):
            raise ValueError("skip_keys must be a list or tuple")
        super().__init__(crypter=crypter, *args, **kwargs)

    def get_internal_type(self):
        return "JSONField"

    def get_db_prep_save(self, value, connection):
        """
        Encrypt all the values in the JSON object before saving to the database.
        """
        if value is None:
            return value

        crypter = self.crypter
        if callable(crypter):
            crypter = crypter()

        # Use the crypter's encrypt_values method
        encrypted_value = crypter.encrypt_values(
            value,
            json_skip_keys=self.skip_keys,
            encoder=self.encoder
        )

        # Call JSONField's get_db_prep_save directly to avoid EncryptedMixin
        return super(django.db.models.JSONField, self).get_db_prep_save(
            encrypted_value, connection)

    def from_db_value(self, value, expression, connection):
        """
        Decrypt all the values in the JSON object after loading from the database.
        """
        if value is None:
            return value

        # Let JSONField handle the JSON deserialization
        value = django.db.models.JSONField.from_db_value(self, value,
                                                         expression,
                                                         connection)

        crypter = self.crypter
        if callable(crypter):
            crypter = crypter()

        return crypter.decrypt_values(value)

    def to_python(self, value):
        """
        Override to prevent EncryptedMixin's decryption
        """
        return super(django.db.models.JSONField, self).to_python(value)

    def validate_max_length(self, value):
        """
        Disable max_length validation as it doesn't apply to JSON fields
        """
        pass





SEARCH_HASH_PREFIX = "xZZx"


def is_hashed_already(data_string: str) -> bool:
    """
    Determines if the provided string is already a hash.

    Args:
        data_string (str): The data to evaluate.

    Returns:
        bool: Whether the data is already hashed.
    """

    if data_string is None:
        return False

    if not isinstance(data_string, str):
        return False

    if not data_string.startswith(SEARCH_HASH_PREFIX):
        return False

    actual_hash = data_string[len(SEARCH_HASH_PREFIX) :]

    if len(actual_hash) != 64:
        return False

    return all([char in string.hexdigits for char in actual_hash])


class EncryptedSearchFieldDescriptor:
    """
    Descriptor class for EncryptedSearchField.
    """

    def __init__(self, field):
        self.field = field

    def __get__(self, instance, owner):
        """
        Gets the underlying plaintext value from the encrypted field.
        """

        if instance is None:
            return self

        if self.field.encrypted_field_name in instance.__dict__:
            decrypted_data = instance.__dict__[self.field.encrypted_field_name]
        else:
            instance.refresh_from_db(fields=[self.field.encrypted_field_name])
            decrypted_data = getattr(instance, self.field.encrypted_field_name)

        # swap data from encrypted_field to search_field
        setattr(instance, self.field.name, decrypted_data)

        return instance.__dict__[self.field.name]

    def __set__(self, instance, value):
        """
        Updates the value on the corresponding encrypted field.
        """

        instance.__dict__[self.field.name] = value
        if not is_hashed_already(value):
            # if the value has been hashed already, don't pass the value to encrypted_field.
            # otherwise will overwrite the real data with an encrypted version of the hash!!
            instance.__dict__[self.field.encrypted_field_name] = value


class EncryptedSearchField(models.CharField):
    """
    A Search field to accompany an Encrypted Field. A keyed hash of the value is stored and searched against.

    The user provided hash_key should be suitably long and random to prevent being able to 'guess' the value
    The user must provide an encrypted_field_name of the corresponding encrypted-data field in the same model.

    Notes:
         - Do not use model.objects.update() unless you update both the SearchField and the associated EncryptedField.
         - Always add a SearchField to a model, don't change/alter an existing regular django field.
         - If using values_list, use the encrypted field, not the search field.
         - To be searchable, the same salt value must be maintained model wide; to change the salt; data needs to be re-saved.

    Note on Defaults:
        To make sure the expected 'default=' value is used (in both SearchField and EncryptedField),
        the SearchField must always use the EncryptedField's 'default=' value.
        This ensures the correct default is used in both fields for:
        1. Initial values in forms
        2. Migrations (adding defaults to existing rows)
        3. Saving model instances
        Having different defaults on the SearchField and Encrypted field, eg only setting
        default on one of them, leads to some unexpected and strange behaviour.

    Limitations:
    - Only supports exact matches
    - Case-insensitive comparisons
    - No partial matches or wildcards
    - Must maintain same salt value across all instances
    """

    description = "A secure SearchField to accompany an EncryptedField"
    descriptor_class = EncryptedSearchFieldDescriptor

    def db_type(self, connection):
        """
        Ensures the field is created as a TextField in the database
        to accommodate the hash length
        """
        return 'text'

    def __init__(self, salt=None, encrypted_field_name=None, *args, **kwargs):
        if salt is None:
            self.salt = getattr(settings, "EJF_SEARCH_FIELD_SALT", "")
        else:
            self.salt = salt

        if encrypted_field_name is None:
            raise ImproperlyConfigured(
                "You must supply the name of the accompanying Encrypted Field that will hold the data"
            )
        if not isinstance(encrypted_field_name, str):
            raise ImproperlyConfigured(
                "'encrypted_field_name' must be a string")

        self.encrypted_field_name = encrypted_field_name

        if kwargs.get("primary_key"):
            raise ImproperlyConfigured(
                "SearchField does not support primary_key=True.")

        if "default" in kwargs:
            # We always use EncryptedField's default.
            raise ImproperlyConfigured(
                f"SearchField does not support 'default='. Set 'default=' on '{self.encrypted_field_name}' instead"
            )

        kwargs["max_length"] = 64 + len(
            SEARCH_HASH_PREFIX)  # will be sha256 hex digest
        kwargs[
            "null"] = True  # should be nullable, in case data field is nullable.
        kwargs[
            "blank"] = True  # to be consistent with 'null'. Forms are not based on SearchField anyway.
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        # Only include kwarg if it's not the default (None)
        if self.salt:
            kwargs["salt"] = self.salt

        if self.encrypted_field_name:
            kwargs["encrypted_field_name"] = self.encrypted_field_name

        return name, path, args, kwargs

    def contribute_to_class(self, cls, name, **kwargs):
        super().contribute_to_class(cls, name, **kwargs)
        setattr(cls, self.name, self.descriptor_class(self))

    def has_default(self):
        """Always use the EncryptedFields default"""
        return self.model._meta.get_field(
            self.encrypted_field_name).has_default()

    def get_default(self):
        """Always use EncryptedField's default."""
        return self.model._meta.get_field(
            self.encrypted_field_name).get_default()

    def get_prep_lookup(self, lookup_type, value):
        """
        Only allow exact lookups since we're searching hashed values.
        """
        if lookup_type != 'exact':
            raise TypeError(
                f"EncryptedSearchField only supports 'exact' lookups, not '{lookup_type}'. "
                f"Partial matches, case-insensitive searches, etc. are not possible with hashed values."
            )
        return self.get_prep_value(value)

    def get_prep_value(self, value):
        if value is None:
            return value
        # coerce to str before encoding and hashing

        # NOTE: not sure what happens when the str format for date/datetime is changed??
        # Should not matter as we are dealing with a datetime object in this case.
        # Eg str(datetime(10, 9, 2020))

        if is_hashed_already(value):
            # if we have hashed this previously, don't do it again
            return value

        # If it's a string, lower case it so search isn't case-sensitive
        if isinstance(value, str):
            value = value.lower()
        else:
            value = str(value)

        salt = self.salt
        if callable(salt):
            salt = salt()

        salted_value = value + salt
        return SEARCH_HASH_PREFIX + hashlib.sha256(
            salted_value.encode()).hexdigest()

    def clean(self, value, model_instance):
        """
        Validate value against the validators from self.encrypted_field_name.
        Any validators on SearchField will be ignored.

        SearchField's 'max_length' constraint will still be enforced at the database
        level, but applied to the saved hash value.
        """
        if model_instance is None:
            # This will happen when calling manage.py createuser/createsuperuser
            return value

        return model_instance._meta.get_field(self.encrypted_field_name).clean(
            value, model_instance)

    def formfield(self, **kwargs):
        """
        Gets the FormField to use for this field; returns the one from the associated
        EncryptedField.
        """

        encfield_kwargs = kwargs.copy()

        if encfield_kwargs.get("label") is None:
            encfield_kwargs.update({"label": capfirst(self.verbose_name)})

        encfield_kwargs.pop("widget", None)

        return self.model._meta.get_field(self.encrypted_field_name).formfield(
            **encfield_kwargs)
