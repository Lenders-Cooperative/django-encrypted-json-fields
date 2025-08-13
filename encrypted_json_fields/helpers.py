"""Helpers for managing encryption methods in Django Encrypted Fields."""


def get_default_crypter(keys: dict):
    """
    Return an instance of the default encryption class as specified by the
    Django setting `EJF_DEFAULT_ENCRYPTION`.

    The setting should be a string (case-insensitive) or a callable returning a string,
    matching the name of a registered encryption method. If not set, defaults to 'fernet'.

    Args:
        keys (dict): Dictionary of encryption keys to pass to the encryption class.

    Raises:
        ValueError: If the setting is missing or does not match a registered encryption class.

    Returns:
        EncryptionInterface: Instance of the selected encryption class.
    """
    # pylint: disable=import-outside-toplevel
    from django.conf import settings

    from .encryption import EncryptionInterface, EncryptionTypes

    # pylint:enable=import-outside-toplevel

    # Retrieve the default encryption method from Django settings
    enc_key = "EJF_DEFAULT_ENCRYPTION"
    default_encryption = getattr(settings, enc_key, None) or getattr(settings, "SECURITY_SETTINGS", {}).get(enc_key)

    # Raise an error if neither setting is defined
    if not default_encryption:
        raise ValueError("EJF default encryption setting is not defined.")

    # Determine the encryption method name (string)
    if isinstance(default_encryption, str):
        encryption_method = default_encryption.lower()
    elif callable(default_encryption):
        # If the setting is a callable, call it and lower the result
        try:
            encryption_method = default_encryption().lower()
        except Exception as e:
            raise ValueError(f"Error executing EJF default encryption callable: {e}.") from e
    else:
        # Fallback to Fernet if not a string or callable
        encryption_method = EncryptionTypes.FERNET.value

    # Search for a registered encryption class matching the method name
    for enc_type, enc_class in EncryptionInterface.get_encryption_registry().items():
        if enc_type == encryption_method:
            return enc_class(keys)

    # No matching encryption class found
    raise ValueError(f"Encryption method '{default_encryption}' is not a registered encryption class.")
