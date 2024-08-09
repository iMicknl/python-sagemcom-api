"""Exceptions for the Sagemcom F@st client."""


class BaseSagemcomException(Exception):
    """Base exception for Sagemcom F@st client."""


# Broad exceptions provided by this library
class BadRequestException(BaseSagemcomException):
    """Bad request."""


class UnauthorizedException(BaseSagemcomException):
    """Unauthorized."""


class UnknownException(BaseSagemcomException):
    """Unknown exception."""


class UnsupportedHostException(BaseSagemcomException):
    """Raised when API is not available on given host."""


# Exceptions provided by SagemCom API
class AccessRestrictionException(BaseSagemcomException):
    """Raised when current user has access restrictions."""


class AuthenticationException(UnauthorizedException):
    """Raised when authentication is not correct."""


class InvalidSessionException(UnauthorizedException):
    """Raised when session is invalid."""


class LoginRetryErrorException(BaseSagemcomException):
    """Raised when too many login retries are attempted."""


class LoginTimeoutException(BaseSagemcomException):
    """Raised when a timeout is encountered during login."""


class NonWritableParameterException(BaseSagemcomException):
    """Raised when provided parameter is not writable."""


class UnknownPathException(BaseSagemcomException):
    """Raised when provided path does not exist."""


class MaximumSessionCountException(BaseSagemcomException):
    """Raised when the maximum session count is reached."""
