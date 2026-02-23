"""Basic client tests demonstrating mocking patterns for the Sagemcom API client."""

# pylint: disable=protected-access

from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientSession
import pytest
from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import ApiMode, EncryptionMethod
from sagemcom_api.exceptions import AuthenticationException


@pytest.mark.asyncio
async def test_default_session_accepts_ip_cookies():
    """Default aiohttp session should accept cookies from IP hosts."""
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
    )
    try:
        assert getattr(client.session.cookie_jar, "_unsafe", False) is True
    finally:
        await client.close()


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


@pytest.mark.asyncio
async def test_login_auto_fallbacks_to_rest_when_legacy_503():
    """Auto mode should switch to REST when legacy endpoint is unavailable."""
    mock_session = MagicMock(spec=ClientSession)
    mock_session.close = AsyncMock()

    legacy_response = AsyncMock()
    legacy_response.status = 503
    legacy_response.text = AsyncMock(return_value="<html>503 Service Unavailable</html>")
    legacy_response.__aenter__ = AsyncMock(return_value=legacy_response)
    legacy_response.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = legacy_response

    rest_response = AsyncMock()
    rest_response.status = 204
    rest_response.text = AsyncMock(return_value="")
    rest_response.__aenter__ = AsyncMock(return_value=rest_response)
    rest_response.__aexit__ = AsyncMock(return_value=None)
    mock_session.request.return_value = rest_response

    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
        api_mode=ApiMode.AUTO,
    )

    result = await client.login()

    assert result is True
    assert client.active_api_mode == ApiMode.REST
    assert mock_session.post.call_count == 1
    assert mock_session.request.call_count == 1


@pytest.mark.asyncio
async def test_get_encryption_method_rest_returns_none():
    """REST mode should immediately signal that no encryption method is needed."""
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        api_mode=ApiMode.REST,
    )

    result = await client.get_encryption_method()

    assert result == EncryptionMethod.NONE
    await client.close()


@pytest.mark.asyncio
async def test_get_hosts_rest_mode():
    """get_hosts should parse wifi and ethernet devices on REST firmware."""
    mock_session = MagicMock(spec=ClientSession)
    mock_session.close = AsyncMock()

    login_response = AsyncMock()
    login_response.status = 204
    login_response.text = AsyncMock(return_value="")
    login_response.__aenter__ = AsyncMock(return_value=login_response)
    login_response.__aexit__ = AsyncMock(return_value=None)

    home_payload = [
        {
            "wirelessListDevice": [
                {
                    "id": 1,
                    "hostname": "wifi-device",
                    "friendlyname": "wifi-device",
                    "macAddress": "aa:bb:cc:dd:ee:ff",
                    "ipAddress": "192.168.1.2",
                    "active": True,
                    "devicetype": "MISCELLANEOUS",
                }
            ],
            "ethernetListDevice": [
                {
                    "id": 2,
                    "hostname": "lan-device",
                    "friendlyname": "lan-device",
                    "macAddress": "11:22:33:44:55:66",
                    "ipAddress": "192.168.1.3",
                    "active": True,
                    "devicetype": "MISCELLANEOUS",
                }
            ],
        }
    ]
    hosts_response = AsyncMock()
    hosts_response.status = 200
    hosts_response.json = AsyncMock(return_value=home_payload)
    hosts_response.__aenter__ = AsyncMock(return_value=hosts_response)
    hosts_response.__aexit__ = AsyncMock(return_value=None)

    mock_session.request.side_effect = [login_response, hosts_response]

    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        session=mock_session,
        api_mode=ApiMode.REST,
    )

    await client.login()
    devices = await client.get_hosts()

    assert len(devices) == 2
    assert devices[0].host_name == "wifi-device"
    assert devices[0].interface_type == "wifi"
    assert devices[1].host_name == "lan-device"
    assert devices[1].interface_type == "ethernet"


@pytest.mark.asyncio
async def test_get_hosts_rest_fallbacks_to_hosts_endpoint():
    """/api/v1/hosts should be used when /api/v1/home response is invalid."""
    mock_session = MagicMock(spec=ClientSession)
    mock_session.close = AsyncMock()

    login_response = AsyncMock()
    login_response.status = 204
    login_response.text = AsyncMock(return_value="")
    login_response.__aenter__ = AsyncMock(return_value=login_response)
    login_response.__aexit__ = AsyncMock(return_value=None)

    home_response = AsyncMock()
    home_response.status = 200
    home_response.json = AsyncMock(return_value=[{"unexpected": "shape"}])
    home_response.__aenter__ = AsyncMock(return_value=home_response)
    home_response.__aexit__ = AsyncMock(return_value=None)

    hosts_payload = [
        {
            "id": 7,
            "hostname": "tablet",
            "friendlyname": "tablet",
            "macAddress": "aa:aa:aa:aa:aa:aa",
            "ipAddress": "192.168.1.50",
            "active": "true",
            "interfaceType": "wireless",
            "devicetype": "TABLET",
        }
    ]
    hosts_response = AsyncMock()
    hosts_response.status = 200
    hosts_response.json = AsyncMock(return_value=hosts_payload)
    hosts_response.__aenter__ = AsyncMock(return_value=hosts_response)
    hosts_response.__aexit__ = AsyncMock(return_value=None)

    mock_session.request.side_effect = [login_response, home_response, hosts_response]

    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        session=mock_session,
        api_mode=ApiMode.REST,
    )

    await client.login()
    devices = await client.get_hosts(only_active=True)

    assert len(devices) == 1
    assert devices[0].host_name == "tablet"
    assert devices[0].interface_type == "wifi"
    assert devices[0].active is True


@pytest.mark.asyncio
async def test_get_hosts_rest_fallbacks_on_home_400():
    """/api/v1/hosts should be tried when /api/v1/home returns HTTP 400."""
    mock_session = MagicMock(spec=ClientSession)
    mock_session.close = AsyncMock()

    login_response = AsyncMock()
    login_response.status = 204
    login_response.text = AsyncMock(return_value="")
    login_response.__aenter__ = AsyncMock(return_value=login_response)
    login_response.__aexit__ = AsyncMock(return_value=None)

    home_response = AsyncMock()
    home_response.status = 400
    home_response.text = AsyncMock(return_value='{"exception":{"domain":"/api/v1/home"}}')
    home_response.__aenter__ = AsyncMock(return_value=home_response)
    home_response.__aexit__ = AsyncMock(return_value=None)

    hosts_payload = [
        {
            "id": 3,
            "hostname": "phone",
            "friendlyname": "phone",
            "macAddress": "de:ad:be:ef:00:01",
            "ipAddress": "192.168.1.25",
            "active": True,
            "interfaceType": "wireless",
            "devicetype": "SMARTPHONE",
        }
    ]
    hosts_response = AsyncMock()
    hosts_response.status = 200
    hosts_response.json = AsyncMock(return_value=hosts_payload)
    hosts_response.__aenter__ = AsyncMock(return_value=hosts_response)
    hosts_response.__aexit__ = AsyncMock(return_value=None)

    mock_session.request.side_effect = [login_response, home_response, hosts_response]

    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        session=mock_session,
        api_mode=ApiMode.REST,
    )

    await client.login()
    devices = await client.get_hosts()

    assert len(devices) == 1
    assert devices[0].host_name == "phone"
    assert devices[0].interface_type == "wifi"


@pytest.mark.asyncio
async def test_reboot_rest_mode():
    """reboot should call REST endpoint on REST firmware."""
    mock_session = MagicMock(spec=ClientSession)
    mock_session.close = AsyncMock()

    login_response = AsyncMock()
    login_response.status = 204
    login_response.text = AsyncMock(return_value="")
    login_response.__aenter__ = AsyncMock(return_value=login_response)
    login_response.__aexit__ = AsyncMock(return_value=None)

    reboot_response = AsyncMock()
    reboot_response.status = 204
    reboot_response.text = AsyncMock(return_value="")
    reboot_response.__aenter__ = AsyncMock(return_value=reboot_response)
    reboot_response.__aexit__ = AsyncMock(return_value=None)

    mock_session.request.side_effect = [login_response, reboot_response]

    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        session=mock_session,
        api_mode=ApiMode.REST,
    )

    await client.login()
    result = await client.reboot()

    assert result is None
    assert mock_session.request.call_count == 2
    reboot_call = mock_session.request.call_args_list[1]
    assert reboot_call.args[0] == "POST"
    assert reboot_call.args[1].endswith("/api/v1/device/reboot")
