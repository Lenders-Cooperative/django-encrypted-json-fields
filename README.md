# django-encrypted-fields

`django-encrypted-fields` is a Django library that provides encrypted versions of Django's standard model fields. It uses the **`cryptography`** library for secure encryption and decryption of data, supporting both AES and Fernet encryption methods. It also includes an **Encrypted JSONField** for secure storage of JSON objects and a **hash-based search field** for secure searches.

---

## Features

- **Encrypted Fields**:

  - Drop-in replacements for Django's fields: `CharField`, `TextField`, `EmailField`, `BooleanField`, `DateField`, `DateTimeField`, `IntegerField`, `JSONField`, etc.
  - Recursively encrypts values for `EncryptedJSONField`.
  - Encryption methods: AES and Fernet.
  - **Crypter** can be static or callable for dynamic initialization.

- **Hash-Based Search Field**:
  - Allows exact, case-insensitive lookups on encrypted fields using a salted hash.
  - Requires a **companion encrypted field**.

---

## Installation

Install the package using `pip`:

```bash
pip install django-encrypted-fields
```

Ensure the required dependencies are installed:

```bash
pip install cryptography pycryptodome
```

---

## Configuration

### Define Encryption Keys

Implementation of this is left up to you. You can define them in your settings.py, or in a more secure way.

```python
ENCRYPTION_KEYS = {
    "aes": [b"your-32-byte-long-aes-key-1"],
    "fernet": [b"your-fernet-key-1", b"your-fernet-key-2"]
}
```

_The keys should come from an env variable or a secure source._

You can use **AES** or **Fernet** encryption by initializing the appropriate crypter.

There is a helper function `get_default_crypter` included to get the default crypter from a settings variable. It should be passed the encryption keys.

Add the following to your `settings.py`:

```python
EJF_SEARCH_FIELD_SALT = "your-salt-for-search-field"  # should be secure, random, and consistent
EJF_ENABLE_ENCRYPTION = True # defaults to True if not found
EJF_DEFAULT_ENCRYPTION = "aes" # only required for using get_default_crypter
```

---

## Usage

### Encrypted Fields

To use encrypted fields, pass a **`crypter`** instance with encryption keys to the field definition. The crypter can also be a **callable** for dynamic configuration.

#### Example Model:

```python
from django.db import models
from .fields import (
    EncryptedCharField,
    EncryptedTextField,
    EncryptedJSONField,
)
from .encryption import AESEncryption, FernetEncryption

# in the case of existing encrypted data, include the keys for the old encryption method
keys = {
    "aes": [b"your-aes-key"],
    "fernet": [b"your-fernet-key"],
}

# Static crypter
aes_crypter = AESEncryption(keys=keys)

class TestModel(models.Model):
    # Encrypted CharField
    enc_char_field = EncryptedCharField(
        max_length=100, crypter=aes_crypter
    )

    # Encrypted TextField with callable crypter
    enc_text_field = EncryptedTextField(
        crypter=lambda: FernetEncryption(keys=keys)
    )

    # Encrypted JSONField
    metadata = EncryptedJSONField(
        crypter=aes_crypter, skip_keys=["public_data"]
    )
```

---

### Encrypted JSONField

The **`EncryptedJSONField`** recursively encrypts the values of keys in the JSON object **except for skipped keys**.

#### Example:

```python
keys = {
    "aes": [b"your-32-byte-aes-key"],
}

class TestModel(models.Model):
    data = EncryptedJSONField(
        crypter=AESEncryption(keys=keys),
        skip_keys=["public_key"]
    )
```

- **`skip_keys`**: A list of keys to exclude from encryption.
- Nested keys are also encrypted recursively.

**Example Data**:

```python
data = {
    "key1": "secret value",
    "key2": {"nested_key": 123},
    "public_key": "this is public"
}
```

**Encrypted Output**:

- `"key1"` → Encrypted
- `"key2"` → Encrypted recursively
- `"public_key"` → Skipped (not encrypted)

---

### Encrypted Search Field

The **`EncryptedSearchField`** hashes and salts values for secure exact lookups. It **must be used alongside a companion encrypted field**.

#### Example:

```python
from .fields import EncryptedCharField, EncryptedSearchField

keys = {
    "aes": [b"your-32-byte-aes-key"]
}

class SearchableModel(models.Model):
    sensitive_data = EncryptedCharField(
        max_length=255, crypter=AESEncryption(keys=keys)
    )
    search_data = EncryptedSearchField(
        encrypted_field_name="sensitive_data"
    )
```

#### Usage:

```python
SearchableModel.objects.create(sensitive_data="secret value")
results = SearchableModel.objects.filter(search_data="secret value")
print(results)
```

**Notes**:

- Only supports **exact matches**.
- Case-insensitive comparisons.
- Use alongside the associated encrypted field.

---

## Crypter Configuration

The `crypter` handles encryption and decryption. You can use **AES** or **Fernet** methods.

### AES Encryption Example:

```python
from .encryption import AESEncryption

keys = {"aes": [b"your-32-byte-long-aes-key"], "fernet": [b"your-fernet-key"]}
aes_crypter = AESEncryption(keys=keys)

encrypted = aes_crypter.encrypt_str("Hello World")
decrypted = aes_crypter.decrypt_str(encrypted)
print(decrypted)  # Outputs: Hello World
```

### Fernet Encryption Example:

```python
from .encryption import FernetEncryption

keys = {"aes": [b"your-32-byte-long-aes-key"], "fernet": [b"your-fernet-key"]}
fernet_crypter = FernetEncryption(keys=keys)

encrypted = fernet_crypter.encrypt_str("Hello World")
decrypted = fernet_crypter.decrypt_str(encrypted)
print(decrypted)  # Outputs: Hello World
```

---

## Notes on SearchField

- Requires an `encrypted_field_name` referencing the associated encrypted field.
- Does not support:
  - Partial matches
  - Wildcards
- Does suppert:
  - Case-insensitive matches

Always query using the **exact value** of the field.

---

## Limitations

1. Encrypted fields **cannot be used for partial lookups** or ordering.
2. `EncryptedSearchField`:
   - Only supports exact matches.
   - Requires consistent `salt` for hashing.
3. Ensure encryption keys are **securely stored** and **not hardcoded** in the codebase.

---

## Adding a New Encryption Method Class

To add a new encryption method, create a new class in the `encryption.py` file that inherits from `EncryptionInterface`.
You can add a matching `EncryptionType` attribute in `constants.py`.

```python
# Example class for a custom encryption method

class MyCustomEncryption(EncryptionInterface):
    @property
    def method_type(self) -> str:
        """
        Return a short string that identifies this new method.
        This value will become part of the prefix for storage/lookup.
        """
        return "mycustom"

    def __init__(self, keys, encoder=None, decoder=None, force=True):
        super().__init__(keys, encoder=encoder, decoder=decoder, force=force)
        # TODO: Initialize any custom components, e.g. your custom key parsing
        self.my_keys = keys.get("mycustom", [])
        # Setup your internal encryption/decryption object if needed

    def encrypt_raw(self, data: bytes) -> bytes:
        """
        Perform the **raw** encryption without adding prefixes or performing
        final transformations like Base64 encoding. Must return bytes.
        """
        # TODO: Implement your custom encryption logic
        # e.g., encrypt using your custom crypto library
        ciphertext = b"..."
        return ciphertext

    def decrypt_internal(self, data: bytes) -> bytes:
        """
        Decrypt the data that was originally produced by encrypt_raw.
        The 'data' argument has already had the prefix removed by the base class.
        """
        # TODO: Implement your custom decryption logic
        plaintext = b"..."
        return plaintext
```

### Register the new class at the bottom of the `encryption.py` file:

```python
EncryptionInterface.register_encryption_method("mycustom", MyCustomEncryption)
```

## TODO

Update commands to work with new code.

---

## Contributing

1. Fork the repository.
2. Install dependencies.
3. Submit a pull request with your changes.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

This library is inspired by Django's native fields and uses the `cryptography` library for secure encryption and decryption.
