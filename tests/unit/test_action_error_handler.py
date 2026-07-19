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


def test_throw_if_error_noop_when_request_succeeded():
    """No exception is raised when the request-level error is not an action error."""
    response = _response("XMO_REQUEST_NO_ERR", ["XMO_UNKNOWN_PATH_ERR"])

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


def test_throw_if_error_ignore_unknown_path_skips_to_next_error():
    """Unknown-path errors are skipped and a later real error is still raised."""
    response = _response(
        "XMO_REQUEST_ACTION_ERR",
        ["XMO_UNKNOWN_PATH_ERR", "XMO_AUTHENTICATION_ERR"],
    )

    with pytest.raises(AuthenticationException):
        ActionErrorHandler.throw_if_error(response, ignore_unknown_path=True)


def test_throw_if_error_ignore_unknown_path_noop_when_only_unknown_paths():
    """A response with only unknown-path errors does not raise when ignoring them."""
    response = _response(
        "XMO_REQUEST_ACTION_ERR",
        ["XMO_UNKNOWN_PATH_ERR", "XMO_UNKNOWN_PATH_ERR"],
    )

    ActionErrorHandler.throw_if_error(response, ignore_unknown_path=True)


# --- throw_if_error_at -----------------------------------------------------


def test_throw_if_error_at_raises_for_indexed_action():
    """The exception for the action at the given index is raised."""
    response = _response(
        "XMO_REQUEST_ACTION_ERR",
        ["XMO_NO_ERR", "XMO_AUTHENTICATION_ERR"],
    )

    with pytest.raises(AuthenticationException):
        ActionErrorHandler.throw_if_error_at(response, 1)


def test_throw_if_error_at_noop_when_action_ok():
    """No exception is raised when the indexed action reports XMO_NO_ERR."""
    response = _response("XMO_REQUEST_ACTION_ERR", ["XMO_NO_ERR"])

    ActionErrorHandler.throw_if_error_at(response, 0)


def test_throw_if_error_at_noop_for_out_of_range_index():
    """An out-of-range index is tolerated rather than raising IndexError."""
    response = _response("XMO_REQUEST_ACTION_ERR", ["XMO_UNKNOWN_PATH_ERR"])

    ActionErrorHandler.throw_if_error_at(response, 5)


def test_throw_if_error_at_ignore_unknown_path():
    """With ignore_unknown_path, an unknown-path error at the index is tolerated."""
    response = _response("XMO_REQUEST_ACTION_ERR", ["XMO_UNKNOWN_PATH_ERR"])

    ActionErrorHandler.throw_if_error_at(response, 0, ignore_unknown_path=True)


def test_throw_if_error_at_still_raises_non_unknown_path_when_ignoring():
    """ignore_unknown_path must not suppress other error types."""
    response = _response("XMO_REQUEST_ACTION_ERR", ["XMO_AUTHENTICATION_ERR"])

    with pytest.raises(AuthenticationException):
        ActionErrorHandler.throw_if_error_at(response, 0, ignore_unknown_path=True)


# --- from_error_description ------------------------------------------------


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("XMO_AUTHENTICATION_ERR", AuthenticationException),
        ("XMO_ACCESS_RESTRICTION_ERR", AccessRestrictionException),
        ("XMO_NON_WRITABLE_PARAMETER_ERR", NonWritableParameterException),
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
