"""Tests for automatic encryption method detection."""

import json

import pytest

from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import EncryptionMethod
from sagemcom_api.exceptions import LoginRetryErrorException


@pytest.mark.asyncio
async def test_detection_stops_when_router_locks_login(mock_session_factory, login_retry_error_response):
    """XMO_LOGIN_RETRY_ERR means the router has locked logins; probing further only extends the lock."""
    mock_session = mock_session_factory([login_retry_error_response] * 3)
    client = SagemcomClient("192.168.1.1", "admin", "admin", session=mock_session)

    with pytest.raises(LoginRetryErrorException):
        await client.get_encryption_method()

    assert mock_session.post.call_count == 1


@pytest.mark.asyncio
async def test_detection_moves_on_after_authentication_error(mock_session_factory, login_auth_error_response, login_success_response):
    """A plain authentication error still means "wrong method", so the next method is tried."""
    mock_session = mock_session_factory([login_auth_error_response, login_success_response, login_success_response])
    client = SagemcomClient("192.168.1.1", "admin", "admin", session=mock_session)

    method = await client.get_encryption_method()

    assert method == EncryptionMethod.MD5_NONCE
    assert mock_session.post.call_count == 3  # two logins and the logout of the probe session


@pytest.mark.asyncio
async def test_detection_closes_the_session_it_opened(mock_session_factory, login_auth_error_response, login_success_response):
    """Firmware that allows a single session (F@st 5670) rejects the caller's login while the probe session is open."""
    mock_session = mock_session_factory([login_auth_error_response, login_success_response, login_success_response])
    client = SagemcomClient("192.168.1.1", "admin", "admin", session=mock_session)

    await client.get_encryption_method()

    request = json.loads(mock_session.post.call_args.kwargs["data"]["req"])["request"]
    assert request["actions"][0]["method"] == "logOut"
    assert request["session-id"] == 12345
    assert client._session_id == 0  # pylint: disable=protected-access


@pytest.mark.asyncio
async def test_detection_survives_a_failed_logout(mock_session_factory, login_success_response):
    """Closing the probe session is best effort: the method is already known when the logout times out."""
    mock_session = mock_session_factory([login_success_response])
    mock_session.post.side_effect = [mock_session.post.return_value, TimeoutError()]
    client = SagemcomClient("192.168.1.1", "admin", "admin", session=mock_session)

    assert await client.get_encryption_method() == EncryptionMethod.MD5
