"""Logic to spot and create ActionErrorExceptions."""

from .const import (
    XMO_ACCESS_RESTRICTION_ERR,
    XMO_AUTHENTICATION_ERR,
    XMO_INVALID_PATH_ERR,
    XMO_LOGIN_RETRY_ERR,
    XMO_MAX_SESSION_COUNT_ERR,
    XMO_NO_ERR,
    XMO_NON_WRITABLE_PARAMETER_ERR,
    XMO_REQUEST_ACTION_ERR,
    XMO_UNKNOWN_PATH_ERR,
)
from .exceptions import (
    AccessRestrictionException,
    AuthenticationException,
    BaseSagemcomException,
    LoginRetryErrorException,
    MaximumSessionCountException,
    NonWritableParameterException,
    UnknownException,
    UnknownPathException,
)

# Firmware differs in which of these it reports for a path that does not exist.
PATH_ERRORS = (XMO_INVALID_PATH_ERR, XMO_UNKNOWN_PATH_ERR)

# These fail the whole request. Actions may still carry a placeholder such as
# XMO_UNKNOWN_PATH_ERR, which must not hide the real cause.
REQUEST_ERRORS = (
    XMO_AUTHENTICATION_ERR,
    XMO_ACCESS_RESTRICTION_ERR,
    XMO_MAX_SESSION_COUNT_ERR,
    XMO_LOGIN_RETRY_ERR,
)


class ActionErrorHandler:
    """Raise exceptions for errors reported in a JSON-req reply."""

    @staticmethod
    def throw_if_error(response, ignore_unknown_paths: bool = False) -> None:
        """Raise for a request-level error, otherwise for the first failed action.

        :param ignore_unknown_paths: skip actions whose path does not exist,
            while still raising any other error
        """
        request_error = response["reply"]["error"]
        request_error_desc = request_error["description"]

        if request_error_desc in REQUEST_ERRORS:
            raise ActionErrorHandler.from_error_description(request_error, request_error_desc)

        if request_error_desc != XMO_REQUEST_ACTION_ERR:
            return

        for action in response["reply"]["actions"]:
            action_error = action["error"]
            action_error_desc = action_error["description"]

            if action_error_desc == XMO_NO_ERR:
                continue

            if ignore_unknown_paths and action_error_desc in PATH_ERRORS:
                continue

            raise ActionErrorHandler.from_error_description(action_error, action_error_desc)

    @staticmethod
    def from_error_description(action_error, action_error_desc) -> BaseSagemcomException:
        """Create the correct exception from an error, for the caller to throw."""
        # pylint: disable=too-many-return-statements

        if action_error_desc == XMO_AUTHENTICATION_ERR:
            return AuthenticationException(action_error)

        if action_error_desc == XMO_ACCESS_RESTRICTION_ERR:
            return AccessRestrictionException(action_error)

        if action_error_desc == XMO_NON_WRITABLE_PARAMETER_ERR:
            return NonWritableParameterException(action_error)

        if action_error_desc in PATH_ERRORS:
            return UnknownPathException(action_error)

        if action_error_desc == XMO_MAX_SESSION_COUNT_ERR:
            return MaximumSessionCountException(action_error)

        if action_error_desc == XMO_LOGIN_RETRY_ERR:
            return LoginRetryErrorException(action_error)

        return UnknownException(action_error)
