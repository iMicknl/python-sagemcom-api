"""Logic to spot and create ActionErrorExceptions."""

from .const import (
    XMO_ACCESS_RESTRICTION_ERR,
    XMO_AUTHENTICATION_ERR,
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
    LoginRetryErrorException,
    MaximumSessionCountException,
    NonWritableParameterException,
    UnknownException,
    UnknownPathException,
)


class ActionErrorHandler:
    """Raised when a requested action has an error."""

    KNOWN_EXCEPTIONS = (
        XMO_AUTHENTICATION_ERR,
        XMO_ACCESS_RESTRICTION_ERR,
        XMO_NON_WRITABLE_PARAMETER_ERR,
        XMO_UNKNOWN_PATH_ERR,
        XMO_MAX_SESSION_COUNT_ERR,
        XMO_LOGIN_RETRY_ERR,
    )

    @staticmethod
    def throw_if_error(response, ignore_unknown_path: bool = False) -> None:
        """Raise the first action-level error, or do nothing if all actions succeeded.

        :param ignore_unknown_path: if True, silently ignore UnknownPathException
        """
        if response["reply"]["error"]["description"] != XMO_REQUEST_ACTION_ERR:
            return

        for action in response["reply"]["actions"]:
            action_error = action["error"]
            action_error_desc = action_error["description"]
            if action_error_desc != XMO_NO_ERR:
                exc = ActionErrorHandler.from_error_description(action_error, action_error_desc)
                if ignore_unknown_path and isinstance(exc, UnknownPathException):
                    continue
                raise exc

    @staticmethod
    def throw_if_error_at(response, index: int, ignore_unknown_path: bool = False) -> None:
        """Raise the error for a specific action, or do nothing if it succeeded.

        :param ignore_unknown_path: if True, silently ignore UnknownPathException
        """
        try:
            action_error = response["reply"]["actions"][index]["error"]
        except (KeyError, IndexError):
            return

        action_error_desc = action_error["description"]
        if action_error_desc == XMO_NO_ERR:
            return

        exc = ActionErrorHandler.from_error_description(action_error, action_error_desc)
        if ignore_unknown_path and isinstance(exc, UnknownPathException):
            return
        raise exc

    @staticmethod
    def from_error_description(action_error, action_error_desc):
        """Create the correct exception from an error, for the caller to throw."""
        # pylint: disable=too-many-return-statements

        if action_error_desc == XMO_AUTHENTICATION_ERR:
            return AuthenticationException(action_error)

        if action_error_desc == XMO_ACCESS_RESTRICTION_ERR:
            return AccessRestrictionException(action_error)

        if action_error_desc == XMO_NON_WRITABLE_PARAMETER_ERR:
            return NonWritableParameterException(action_error)

        if action_error_desc == XMO_UNKNOWN_PATH_ERR:
            return UnknownPathException(action_error)

        if action_error_desc == XMO_MAX_SESSION_COUNT_ERR:
            return MaximumSessionCountException(action_error)

        if action_error_desc == XMO_LOGIN_RETRY_ERR:
            return LoginRetryErrorException(action_error)

        return UnknownException(action_error)
