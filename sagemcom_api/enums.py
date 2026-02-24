"""Enums for the Sagemcom F@st client."""

from enum import unique
import sys

# Since we support Python versions lower than 3.11, we use
# a backport for StrEnum when needed.
if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from backports.strenum import StrEnum


@unique
class EncryptionMethod(StrEnum):
    """Encryption method defining the password hash."""

    MD5 = "MD5"
    MD5_NONCE = "MD5_NONCE"
    SHA512 = "SHA512"
    NONE = "NONE"


@unique
class ApiMode(StrEnum):
    """API mode to use when communicating with the router."""

    AUTO = "auto"
    LEGACY = "legacy"
    REST = "rest"
