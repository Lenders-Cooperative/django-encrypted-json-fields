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
    # handle the possibility of this being a callable
    if isinstance(default_encryption, str):
        encryption_method = default_encryption.lower()
    elif callable(default_encryption):
        try:
            encryption_method = default_encryption().lower()
        except Exception as e:
            raise ValueError(
                f"Error executing EJF_DEFAULT_ENCRYPTION callable: {e}")
    else:
        # Define a default encryption method if none is set
        encryption_method = "fernet"


    # Match the setting to a registered encryption class by prefix
    for method_type, encryption_class in EncryptionMethod._encryption_registry.items():
        # Normalize the prefix for comparison

        if method_type == encryption_method:
            return encryption_class(keys)

    # If no match is found, raise an error
    raise ValueError(
        f"Encryption method '{default_encryption}' is not a registered encryption class.")

def build_crypter(keys):
    if not isinstance(keys, (tuple, list)):
        keys = [
            keys,
        ]
    return get_default_crypter(keys)