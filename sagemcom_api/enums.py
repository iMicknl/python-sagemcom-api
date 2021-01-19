"""Enums for the Sagemcom F@st client."""

from enum import Enum


class EncryptionMethod(Enum):
    def __str__(self):
        return str(self.value)

    MD5 = "md5"
    SHA512 = "sha512"
    UNKNOWN = "unknown"
