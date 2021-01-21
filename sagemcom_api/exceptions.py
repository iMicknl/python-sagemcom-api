"""Exceptions for the Sagemcom F@st client."""


# Exceptions provided by SagemCom API
class AccessRestrictionException(Exception):
    """Raised when current user has access restrictions."""

    pass


class AuthenticationException(Exception):
    """Raised when authentication is not correct."""

    pass


class LoginTimeoutException(Exception):
    """Raised when a timeout is encountered during login."""

    pass


class NonWritableParameterException(Exception):
    """Raised when provided parameter is not writable."""

    pass


class UnknownPathException(Exception):
    """Raised when provided path does not exist."""

    pass


# Exceptions provided by this library
# TODO Validate our own errors
class BadRequestException(Exception):
    """TODO."""

    pass


class UnauthorizedException(Exception):
    """TODO."""

    pass


class UnknownException(Exception):
    """TODO."""

    pass
