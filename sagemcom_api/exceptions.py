"""Exceptions for the Sagemcom F@st client."""


# Exceptions provided by SagemCom API
class AccessRestrictionException(Exception):
    """Raised when current user has access restrictions."""


class AuthenticationException(Exception):
    """Raised when authentication is not correct."""


class LoginTimeoutException(Exception):
    """Raised when a timeout is encountered during login."""


class NonWritableParameterException(Exception):
    """Raised when provided parameter is not writable."""


class UnknownPathException(Exception):
    """Raised when provided path does not exist."""


class MaximumSessionCountException(Exception):
    """Raised when the maximum session count is reached."""


# Exceptions provided by this library
# TODO Validate our own errors
class BadRequestException(Exception):
    """TODO."""


class UnauthorizedException(Exception):
    """TODO."""


class UnknownException(Exception):
    """TODO."""
