"""Enums for the Sagemcom F@st client."""

from enum import StrEnum, unique


@unique
class EncryptionMethod(StrEnum):
    """Encryption method defining the password hash."""

    MD5 = "MD5"
    MD5_NONCE = "MD5_NONCE"
    SHA512 = "SHA512"


@unique
class ApiMode(StrEnum):
    """API mode to use when communicating with the router."""

    AUTO = "auto"
    LEGACY = "legacy"
    REST = "rest"
