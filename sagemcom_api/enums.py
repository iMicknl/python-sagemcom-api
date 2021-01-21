"""Enums for the Sagemcom F@st client."""

from enum import Enum


class EncryptionMethod(Enum):
    """Encryption method defining the password hash."""

    MD5 = "MD5"
    SHA512 = "SHA512"
