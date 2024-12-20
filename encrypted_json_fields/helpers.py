from django.conf import settings


def get_default_crypter(keys: dict):
    """
    Returns the crypter class based on the Django setting `EJF_DEFAULT_ENCRYPTION`.
    This setting should match the name of a registered encryption class.

    Args:
        keys (dict): A dictionary of encryption keys.

    Returns:
        EncryptionMethod: An instance of the selected encryption class.

    Raises:
        ValueError: If the default encryption setting is not set or the class is not registered.
    """
    # Import the EncryptionMethod base class to access the registry
    from .encryption import EncryptionMethod

    # Get the default encryption method from settings
    default_encryption = getattr(settings, "EJF_DEFAULT_ENCRYPTION", None)
    if not default_encryption:
        raise ValueError("EJF_DEFAULT_ENCRYPTION setting is not defined.")

    # Normalize the setting (case-insensitive, remove special characters)
    default_encryption = default_encryption.lower().strip().replace(":", "")

    # Match the setting to a registered encryption class by prefix
    for prefix, encryption_class in EncryptionMethod._encryption_registry.items():
        # Normalize the prefix for comparison
        normalized_prefix = prefix.decode().lower().strip().replace(":", "")
        if normalized_prefix == default_encryption:
            return encryption_class(keys)

    # If no match is found, raise an error
    raise ValueError(
        f"Encryption method '{default_encryption}' is not a registered encryption class.")
