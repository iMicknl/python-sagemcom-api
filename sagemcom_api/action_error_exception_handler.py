"""Logic to spot and create ActionErrorExceptions"""

from sagemcom_api.const import (
    XMO_ACCESS_RESTRICTION_ERR,
    XMO_AUTHENTICATION_ERR,
    XMO_LOGIN_RETRY_ERR,
    XMO_MAX_SESSION_COUNT_ERR,
    XMO_NON_WRITABLE_PARAMETER_ERR,
    XMO_NO_ERR,
    XMO_REQUEST_ACTION_ERR,
    XMO_UNKNOWN_PATH_ERR
)
from sagemcom_api.exceptions import (
    AccessRestrictionException,
    AuthenticationException,
    LoginRetryErrorException,
    MaximumSessionCountException,
    NonWritableParameterException,
    UnknownException,
    UnknownPathException
)


class ActionErrorHandler:
    """Raised when a requested action has an error"""

    KNOWN_EXCEPTIONS = (
        XMO_AUTHENTICATION_ERR,
        XMO_ACCESS_RESTRICTION_ERR,
        XMO_NON_WRITABLE_PARAMETER_ERR,
        XMO_UNKNOWN_PATH_ERR,
        XMO_MAX_SESSION_COUNT_ERR,
        XMO_LOGIN_RETRY_ERR
    )

    @staticmethod
    def throw_if(response):
        """For anywhere that needs the old single-exception behaviour"""

        if response["reply"]["error"]["description"] != XMO_REQUEST_ACTION_ERR:
            return

        actions = response["reply"]["actions"]
        for action in actions:

            action_error = action["error"]
            action_error_desc = action_error["description"]

            if action_error_desc == XMO_NO_ERR:
                continue

            raise ActionErrorHandler.from_error_description(action_error, action_error_desc)

    @staticmethod
    def is_unknown_exception(desc):
        """
        True/false if the ActionError is one of our known types
        """

        return False if desc == XMO_NO_ERR else desc not in ActionErrorHandler.KNOWN_EXCEPTIONS

    @staticmethod
    def from_error_description(action_error, action_error_desc):
        """
        Create the correct exception from an error, for the caller to throw
        """
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
