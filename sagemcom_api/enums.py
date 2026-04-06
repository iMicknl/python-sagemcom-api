"""Enums for the Sagemcom F@st client."""

from enum import StrEnum, unique


@unique
class EncryptionMethod(StrEnum):
    """Encryption method defining the password hash."""

    MD5 = "MD5"
    MD5_NONCE = "MD5_NONCE"
    SHA512 = "SHA512"
