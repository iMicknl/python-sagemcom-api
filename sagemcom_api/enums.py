"""Enums for the Sagemcom F@st client."""

from enum import Enum


class EncryptionMethod(Enum):
    """TODO."""

    def __str__(self):
        """TODO."""
        return str(self.value)

    MD5 = "md5"
    SHA512 = "sha512"
    UNKNOWN = "unknown"
