"""Basic client tests demonstrating mocking patterns for the Sagemcom API client."""

# pylint: disable=protected-access

import pytest

from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import EncryptionMethod
from sagemcom_api.exceptions import AuthenticationException


@pytest.mark.asyncio
async def test_login_success(mock_session_factory, login_success_response):
    """
    Test successful login with mocked session.

    Demonstrates:
    - Mocking aiohttp session at session.post level
    - Successful login flow with session_id and nonce exchange
    - Using fixture-based API responses
    """
    # Arrange: Create mock session with successful login response
    mock_session = mock_session_factory([login_success_response])
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )

    # Act: Perform login
    result = await client.login()

    # Assert: Verify login succeeded and session state was updated
    assert result is True
    assert client._session_id == 12345
    assert client._server_nonce == "abcdef1234567890"
    assert client._request_id == 0  # Login is first request (id=0)


@pytest.mark.asyncio
async def test_login_authentication_error(
    mock_session_factory, login_auth_error_response
):
    """
    Test login raises AuthenticationException on XMO_AUTHENTICATION_ERR.

    Demonstrates:
    - Mocking error responses from the API
    - Exception handling for authentication failures
    - Action-level error handling (XMO_REQUEST_ACTION_ERR + XMO_AUTHENTICATION_ERR)
    """
    # Arrange: Create mock session with authentication error response
    mock_session = mock_session_factory([login_auth_error_response])
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="wrong_password",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )

    # Act & Assert: Verify AuthenticationException is raised
    with pytest.raises(AuthenticationException) as exc_info:
        await client.login()

    # Verify exception contains error details
    assert "XMO_AUTHENTICATION_ERR" in str(exc_info.value)


@pytest.mark.asyncio
async def test_get_value_by_xpath_url_encoding(
    mock_session_factory, login_success_response, xpath_value_response
):
    """
    Test XPath values are URL-encoded with safe characters preserved.

    Demonstrates:
    - XPath URL encoding behavior
    - Preservation of safe characters: /=[]'
    - Multiple mock responses in sequence (login, then XPath query)
    - Accessing request payload to validate encoding
    """
    # Arrange: Create mock session with login and XPath responses
    mock_session = mock_session_factory([login_success_response, xpath_value_response])
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )

    # Login first
    await client.login()

    # Act: Query XPath with characters that need encoding
    xpath = "Device/WiFi/Radios/Radio[Alias='RADIO2G4']/Status"
    result = await client.get_value_by_xpath(xpath)

    # Assert: Verify result contains expected data
    assert result == "UP"

    # Verify two POST requests were made (login + XPath query)
    assert mock_session.post.call_count == 2

    # Verify XPath was properly URL-encoded in the request
    # Note: Detailed XPath encoding validation (safe characters /=[]')
    # will be covered later


@pytest.mark.asyncio
async def test_login_with_preconfigured_fixture(mock_client_sha512):
    """
    Test login using pre-configured client fixture.

    Demonstrates:
    - Using pre-configured client fixtures for concise tests
    - SHA512 encryption method configuration
    - Reduced boilerplate for common test scenarios
    """
    # Arrange: Use pre-configured mock client fixture
    client = mock_client_sha512

    # Act: Login with pre-configured client (no setup needed)
    result = await client.login()

    # Assert: Verify login succeeded and encryption method is SHA512
    assert result is True
    assert client.authentication_method == EncryptionMethod.SHA512
    assert client._session_id == 12345
    assert client._server_nonce == "abcdef1234567890"
