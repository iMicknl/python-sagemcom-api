"""Exceptions for the Sagemcom F@st client."""


class UnauthorizedException(Exception):
    pass


class TimeoutException(Exception):
    pass


class BadRequestException(Exception):
    pass


class UnknownException(Exception):
    pass
