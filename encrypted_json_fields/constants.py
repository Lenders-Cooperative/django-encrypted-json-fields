"""Constants utilized in the encryption module."""

from enum import Enum


class EncryptionTypes(Enum):
    """
    Simple class to store the encryption types. If you add a new encryption
    class, you can add a matching attribute here.
    """

    AES = "aes"  # CBC mode
    AES_GCM = "aes_gcm"
    FERNET = "fernet"
