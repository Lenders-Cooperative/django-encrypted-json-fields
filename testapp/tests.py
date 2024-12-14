import pytest
from .models import TestModel, TestSearchableModel
from encrypted_json_fields.encryption import FernetEncryption, AESEncryption

@pytest.fixture(scope="module")
def fernet_keys():
    return ["your_fernet_key_1", "your_fernet_key_2"]

@pytest.fixture(scope="module")
def aes_keys():
    return ["your_aes_key_1", "your_aes_key_2"]

@pytest.fixture
def setup_fernet_crypter(fernet_keys):
    TestModel.set_crypter(FernetEncryption, fernet_keys)
    TestSearchableModel.set_crypter(FernetEncryption, fernet_keys)

@pytest.fixture
def setup_aes_crypter(aes_keys):
    TestModel.set_crypter(AESEncryption, aes_keys)
    TestSearchableModel.set_crypter(AESEncryption, aes_keys)


def test_model_fernet_encryption(setup_fernet_crypter):
    instance = TestModel.objects.create(
        enc_char_field="Sensitive Data",
        enc_text_field="Another sensitive text",
        enc_boolean_field=True,
        enc_json_field={"key": "value"}
    )

    assert instance.enc_char_field == "Sensitive Data"
    assert instance.enc_text_field == "Another sensitive text"
    assert instance.enc_boolean_field is True
    assert instance.enc_json_field == {"key": "value"}

    raw_instance = TestModel.objects.raw("SELECT enc_char_field FROM test_app_testmodel WHERE id=%s", [instance.id])
    assert raw_instance != "Sensitive Data"


def test_model_aes_encryption(setup_aes_crypter):
    instance = TestModel.objects.create(
        enc_char_field="Sensitive Data AES",
        enc_text_field="Another sensitive text AES",
        enc_boolean_field=False,
        enc_json_field={"nested": {"key": "value"}}
    )

    assert instance.enc_char_field == "Sensitive Data AES"
    assert instance.enc_text_field == "Another sensitive text AES"
    assert instance.enc_boolean_field is False
    assert instance.enc_json_field == {"nested": {"key": "value"}}

    raw_instance = TestModel.objects.raw("SELECT enc_char_field FROM test_app_testmodel WHERE id=%s", [instance.id])
    assert raw_instance != "Sensitive Data AES"


def test_searchable_model(setup_fernet_crypter):
    instance = TestSearchableModel.objects.create(
        enc_char_field="Searchable Data",
        enc_date_field="2024-12-13",
        enc_integer_field=123
    )

    assert instance.enc_char_field == "Searchable Data"
    assert instance.char_field.startswith("xZZx")

    assert instance.enc_date_field == "2024-12-13"
    assert instance.date_field.startswith("xZZx")

    assert instance.enc_integer_field == 123
    assert instance.integer_field.startswith("xZZx")
