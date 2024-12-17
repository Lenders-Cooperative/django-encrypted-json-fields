import os
from unittest.mock import patch
from django.test import TestCase, TransactionTestCase
import datetime
from datetime import date, timedelta
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.utils import timezone
from encrypted_json_fields.encryption import FernetEncryption
from testapp.models import TestModel, TestSearchableModel, CrypterConfigMixin
from cryptography.fernet import Fernet
from django.db import models
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
)
from django.apps import apps


class EncryptedFieldsBaseTestCase:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keys = {
            'fernet': [Fernet.generate_key()],
            'aes': [os.urandom(32)]
        }

    def setUp(self):
        super().setUp()
        self.crypter = FernetEncryption(keys=self.__class__.keys)
        TestModel.crypter_class = FernetEncryption
        TestModel.crypter_keys = self.__class__.keys
        TestSearchableModel.crypter_class = FernetEncryption
        TestSearchableModel.crypter_keys = self.__class__.keys

        for model in [TestModel, TestSearchableModel]:
            for field in model._meta.fields:
                if isinstance(field, (EncryptedCharField, EncryptedTextField,
                                    EncryptedDateField,
                                    EncryptedDateTimeField,
                                    EncryptedBooleanField,
                                    EncryptedIntegerField,
                                    EncryptedPositiveIntegerField,
                                    EncryptedSmallIntegerField,
                                    EncryptedPositiveSmallIntegerField,
                                    EncryptedBigIntegerField,
                                    EncryptedJSONField)):
                    field._crypter = lambda: self.crypter

    def create_test_model(self, **kwargs):
        """Helper method to create a test model with default values"""
        defaults = {
            'enc_char_field': "default",
            'enc_text_field': "default text",
            'enc_boolean_field': True,
            'enc_json_field': {},
            'enc_date_field': None,
            'enc_datetime_field': None,
            'enc_integer_field': None,
            'enc_positive_integer_field': None,
            'enc_small_integer_field': None,
            'enc_positive_small_integer_field': None,
            'enc_big_integer_field': None
        }
        defaults.update(kwargs)
        model = TestModel(**defaults)
        model.save()
        return model

    def tearDown(self):
        TestModel.crypter_class = None
        TestModel.crypter_keys = []
        TestSearchableModel.crypter_class = None
        TestSearchableModel.crypter_keys = []
        super().tearDown()


class EncryptedFieldsTests(EncryptedFieldsBaseTestCase, TestCase):

    def test_encrypted_char_field(self):
        """Test EncryptedCharField with various values"""
        test_values = [
            "Regular string",
            "Special chars: !@#$%^&*()",
            "Unicode: 你好世界",
            "",  # Empty string
            "a" * 100,  # Max length
        ]
        for value in test_values:
            model = self.create_test_model(enc_char_field=value)
            loaded = TestModel.objects.get(pk=model.pk)
            self.assertEqual(loaded.enc_char_field, value)

    def test_encrypted_text_field(self):
        """Test EncryptedTextField with various values"""
        test_values = [
            "Short text",
            "Long text " * 1000,
            "Multiple\nLine\nText",
            "",  # Empty text
        ]
        for value in test_values:
            model = self.create_test_model(enc_text_field=value)
            loaded = TestModel.objects.get(pk=model.pk)
            self.assertEqual(loaded.enc_text_field, value)

    def test_encrypted_date_fields(self):
        """Test EncryptedDateField functionality"""

        # First verify encryption is working
        test_date = date(2023, 1, 1)
        model = self.create_test_model(enc_date_field=test_date)

        # Check raw value in database is encrypted
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT enc_date_field FROM testapp_testmodel WHERE id = %s",
                [model.pk]
            )
            raw_value = cursor.fetchone()[0]
            print(f"Raw encrypted value: {raw_value}")
            self.assertTrue(self.crypter.is_encrypted(raw_value))

        # Now test auto_now behavior across different dates
        initial_datetime = timezone.now().replace(year=2024, month=1, day=1,
                                                  hour=12, minute=0)
        with patch('django.utils.timezone.now') as mock_now:
            # Set initial date
            mock_now.return_value = initial_datetime
            print(f"Mocked initial datetime: {mock_now()}")

            model = self.create_test_model()
            original_date = model.enc_date_now_field
            print(f"Original date saved: {original_date}")

            # Change to next day
            next_day_datetime = initial_datetime + timedelta(days=1)
            mock_now.return_value = next_day_datetime
            print(f"Mocked next day datetime: {mock_now()}")

            # Force field update to trigger save
            model.enc_char_field = "new value next day"
            model.save()

            # Get a fresh instance from the database
            fresh_model = TestModel.objects.get(pk=model.pk)
            print(f"Date from fresh model: {fresh_model.enc_date_now_field}")

            self.assertNotEqual(fresh_model.enc_date_now_field, original_date)
            self.assertEqual(fresh_model.enc_date_now_field,
                             next_day_datetime.date())

            # Verify encryption
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT enc_date_now_field FROM testapp_testmodel WHERE id = %s",
                    [fresh_model.pk]
                )
                raw_value = cursor.fetchone()[0]
                print(f"Raw encrypted value for auto_now field: {raw_value}")
                self.assertTrue(self.crypter.is_encrypted(raw_value))

    def test_encrypted_datetime_field(self):
        """Test EncryptedDateTimeField functionality"""
        from datetime import datetime, timezone

        test_datetimes = [
            datetime.now(timezone.utc),
            datetime(2023, 1, 1, 12, 0, tzinfo=timezone.utc),
            datetime(2000, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        ]

        for test_datetime in test_datetimes:
            model = self.create_test_model(enc_datetime_field=test_datetime)
            loaded = TestModel.objects.get(pk=model.pk)
            self.assertEqual(loaded.enc_datetime_field, test_datetime)

    def test_encrypted_boolean_field(self):
        """Test EncryptedBooleanField functionality"""
        for value in [True, False]:
            model = self.create_test_model(enc_boolean_field=value)
            loaded = TestModel.objects.get(pk=model.pk)
            self.assertEqual(loaded.enc_boolean_field, value)

    def test_encrypted_integer_fields(self):
        """Test all integer field types"""
        test_cases = [
            ('enc_integer_field', [-1000, 0, 1000]),
            ('enc_positive_integer_field', [0, 1, 1000]),
            ('enc_small_integer_field', [-32768, 0, 32767]),
            ('enc_positive_small_integer_field', [0, 1, 32767]),
            ('enc_big_integer_field',
             [-9223372036854775808, 0, 9223372036854775807])
        ]

        for field_name, values in test_cases:
            for value in values:
                model = self.create_test_model(**{field_name: value})
                loaded = TestModel.objects.get(pk=model.pk)
                self.assertEqual(getattr(loaded, field_name), value)

    def test_encrypted_json_field(self):
        """Test EncryptedJSONField with various JSON structures"""
        test_values = [
            {},  # Empty dict - should remain empty
            {"string": "value"},  # Simple string value should be encrypted
            {"number": 123},  # Numbers should be encrypted
            {"boolean": True},  # Booleans should be encrypted
            {"null": None},  # Null should remain null
            {"nested": {"key": "value"}},  # Nested values should be encrypted
            {"list": [1, 2, 3]},  # List values should be encrypted
            {"complex": {
                "string": "value",
                "number": 123,
                "boolean": True,
                "null": None,
                "list": [1, "2", 3.0, False],
                "nested": {"key": "value"}
            }},
            [],  # Empty list - should remain empty
            [1, 2, 3],  # List values should be encrypted
            ["a", "b", "c"],  # List string values should be encrypted
            [{"key": "value"}, {"key2": "value2"}]
            # Nested dict values should be encrypted
        ]

        for value in test_values:
            model = self.create_test_model(enc_json_field=value)
            loaded = TestModel.objects.get(pk=model.pk)
            decrypted = loaded.enc_json_field

            # Test structure remains the same
            self.assertEqual(type(decrypted), type(value))

            if isinstance(value, dict):
                self.assertEqual(set(decrypted.keys()), set(value.keys()))
                for k, v in value.items():
                    if v is not None:  # None values should remain None
                        if isinstance(v, (dict, list)):
                            # Recursively check nested structures
                            self.assertEqual(type(decrypted[k]), type(v))
                        else:
                            # Values should be decrypted back to original
                            self.assertEqual(decrypted[k], v)
            elif isinstance(value, list):
                self.assertEqual(len(decrypted), len(value))
                for i, v in enumerate(value):
                    if v is not None:
                        if isinstance(v, (dict, list)):
                            # Recursively check nested structures
                            self.assertEqual(type(decrypted[i]), type(v))
                        else:
                            # Values should be decrypted back to original
                            self.assertEqual(decrypted[i], v)

    def test_searchable_fields(self):
        """Test SearchableField functionality for all field types"""
        # Test char field searching
        char_value = "searchable text"
        test_date = date(2023, 12, 14)
        test_integer = 42

        # Create model using all search fields
        search_model = TestSearchableModel.objects.create(
            char_field=char_value,
            date_field=test_date,
            integer_field=test_integer
        )

        # Force a refresh
        search_model.refresh_from_db()

        # Test char field search
        char_found = TestSearchableModel.objects.filter(
            char_field=char_value
        ).exists()

        self.assertTrue(char_found)

        # Test date field search
        date_found = TestSearchableModel.objects.filter(
            date_field=test_date
        ).exists()

        self.assertTrue(date_found)

        # Test integer field search
        integer_found = TestSearchableModel.objects.filter(
            integer_field=test_integer
        ).exists()

        self.assertTrue(integer_found)

        # Test that searching with wrong values returns no results
        wrong_date = date(2022, 1, 1)
        wrong_integer = 99

        self.assertFalse(
            TestSearchableModel.objects.filter(date_field=wrong_date).exists()
        )
        self.assertFalse(
            TestSearchableModel.objects.filter(
                integer_field=wrong_integer).exists()
        )

    def test_null_handling(self):
        """Test handling of null values"""
        nullable_fields = [
            'enc_date_field',
            'enc_datetime_field',
            'enc_integer_field',
            'enc_positive_integer_field',
            'enc_small_integer_field',
            'enc_positive_small_integer_field',
            'enc_big_integer_field'
        ]

        # Test setting fields to None
        model = self.create_test_model(
            **{field: None for field in nullable_fields})
        loaded = TestModel.objects.get(pk=model.pk)

        for field in nullable_fields:
            self.assertIsNone(getattr(loaded, field))


class EncryptedFieldsValidationTests(EncryptedFieldsBaseTestCase, TransactionTestCase):

    def test_field_validation(self):
        """Test field validation"""
        with transaction.atomic():
            # Test CharField max_length
            model = TestModel(enc_char_field="x" * 101)
            with self.assertRaises(ValidationError):
                model.full_clean()

            # Test positive integer validations
            with self.assertRaises(Exception):
                TestModel.objects.create(enc_positive_integer_field=-1)

            with self.assertRaises(Exception):
                TestModel.objects.create(enc_positive_small_integer_field=-1)

            # Test integer range validations
            with self.assertRaises(Exception):
                TestModel.objects.create(
                    enc_small_integer_field=32768)  # Exceeds SmallIntegerField max

            with self.assertRaises(Exception):
                TestModel.objects.create(
                    enc_small_integer_field=-32769)  # Below SmallIntegerField min

            with self.assertRaises(Exception):
                TestModel.objects.create(
                    enc_positive_small_integer_field=32768)  # Exceeds PositiveSmallIntegerField max

            # Test date field validation
            with self.assertRaises(Exception):
                TestModel.objects.create(enc_date_field="not-a-date")

            # Test datetime field validation
            with self.assertRaises(Exception):
                TestModel.objects.create(enc_datetime_field="not-a-datetime")

            # Test boolean field validation
            with self.assertRaises(Exception):
                TestModel.objects.create(enc_boolean_field="not-a-boolean")

            # Test JSON field validation
            with self.assertRaises(Exception):
                TestModel.objects.create(enc_json_field="invalid-json")

    def tearDown(self):
        try:
            with transaction.atomic():
                TestModel.objects.all().delete()
                TestSearchableModel.objects.all().delete()
        except:
            transaction.rollback()
            TestModel.objects.all().delete()
            TestSearchableModel.objects.all().delete()
        super().tearDown()
