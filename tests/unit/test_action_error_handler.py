"""Unit tests for ActionErrorHandler."""

import pytest

from sagemcom_api.action_error_exception_handler import ActionErrorHandler
from sagemcom_api.exceptions import (
    AccessRestrictionException,
    AuthenticationException,
    LoginRetryErrorException,
    MaximumSessionCountException,
    NonWritableParameterException,
    UnknownException,
    UnknownPathException,
)


def _response(request_desc, action_descs):
    """Build a minimal JSON-req reply with the given request and action errors."""
    return {
        "reply": {
            "error": {"description": request_desc},
            "actions": [{"error": {"description": desc}} for desc in action_descs],
        }
    }


# --- throw_if_error --------------------------------------------------------


@pytest.mark.parametrize("request_desc", ["XMO_REQUEST_NO_ERR", "Ok"])
def test_throw_if_error_noop_when_request_succeeded(request_desc):
    """No exception is raised when the request-level error indicates success."""
    response = _response(request_desc, ["XMO_UNKNOWN_PATH_ERR"])

    # Must not raise even though an action carries an error description, because
    # the request-level error indicates overall success.
    ActionErrorHandler.throw_if_error(response)


def test_throw_if_error_noop_when_all_actions_ok():
    """No exception is raised when every action reports XMO_NO_ERR."""
    response = _response("XMO_REQUEST_ACTION_ERR", ["XMO_NO_ERR", "XMO_NO_ERR"])

    ActionErrorHandler.throw_if_error(response)


def test_throw_if_error_raises_first_action_error():
    """The first erroring action determines the raised exception."""
    response = _response(
        "XMO_REQUEST_ACTION_ERR",
        ["XMO_NO_ERR", "XMO_UNKNOWN_PATH_ERR", "XMO_AUTHENTICATION_ERR"],
    )

    with pytest.raises(UnknownPathException):
        ActionErrorHandler.throw_if_error(response)


def test_throw_if_error_ignore_unknown_paths_skips_to_next_error():
    """Unknown-path errors are skipped and a later real error is still raised."""
    response = _response(
        "XMO_REQUEST_ACTION_ERR",
        ["XMO_UNKNOWN_PATH_ERR", "XMO_INVALID_PATH_ERR", "XMO_AUTHENTICATION_ERR"],
    )

    with pytest.raises(AuthenticationException):
        ActionErrorHandler.throw_if_error(response, ignore_unknown_paths=True)


@pytest.mark.parametrize("path_error", ["XMO_INVALID_PATH_ERR", "XMO_UNKNOWN_PATH_ERR"])
def test_throw_if_error_ignore_unknown_paths_noop_when_only_path_errors(path_error):
    """Both missing-path descriptions are tolerated when explicitly ignored."""
    response = _response("XMO_REQUEST_ACTION_ERR", ["XMO_NO_ERR", path_error])

    ActionErrorHandler.throw_if_error(response, ignore_unknown_paths=True)


@pytest.mark.parametrize(
    ("request_desc", "expected"),
    [
        ("XMO_AUTHENTICATION_ERR", AuthenticationException),
        ("XMO_ACCESS_RESTRICTION_ERR", AccessRestrictionException),
        ("XMO_MAX_SESSION_COUNT_ERR", MaximumSessionCountException),
        ("XMO_LOGIN_RETRY_ERR", LoginRetryErrorException),
    ],
)
@pytest.mark.parametrize("ignore_unknown_paths", [False, True])
def test_throw_if_error_request_level_error_wins_over_action_placeholder(request_desc, expected, ignore_unknown_paths):
    """A request-level error is raised even if the actions only report a missing path."""
    response = _response(request_desc, ["XMO_UNKNOWN_PATH_ERR"])

    with pytest.raises(expected):
        ActionErrorHandler.throw_if_error(response, ignore_unknown_paths=ignore_unknown_paths)


# --- from_error_description ------------------------------------------------


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("XMO_AUTHENTICATION_ERR", AuthenticationException),
        ("XMO_ACCESS_RESTRICTION_ERR", AccessRestrictionException),
        ("XMO_NON_WRITABLE_PARAMETER_ERR", NonWritableParameterException),
        ("XMO_INVALID_PATH_ERR", UnknownPathException),
        ("XMO_UNKNOWN_PATH_ERR", UnknownPathException),
        ("XMO_MAX_SESSION_COUNT_ERR", MaximumSessionCountException),
        ("XMO_LOGIN_RETRY_ERR", LoginRetryErrorException),
        ("SOMETHING_UNEXPECTED", UnknownException),
    ],
)
def test_from_error_description_maps_to_exception(description, expected):
    """Each known description maps to its exception; anything else is UnknownException."""
    action_error = {"description": description}

    exc = ActionErrorHandler.from_error_description(action_error, description)

    assert isinstance(exc, expected)
