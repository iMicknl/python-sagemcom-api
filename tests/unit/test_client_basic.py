"""Basic client tests demonstrating mocking patterns for the Sagemcom API client."""

# pylint: disable=protected-access

from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import ClientSession

from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import ApiMode, EncryptionMethod
from sagemcom_api.exceptions import (
    AuthenticationException,
    InvalidSessionException,
    LoginRetryErrorException,
    NonWritableParameterException,
    UnknownPathException,
)


@pytest.mark.asyncio
async def test_response_with_invalid_utf8_is_parsed():
    """Test malformed UTF-8 in a router response does not discard valid JSON."""
    response_body = b'{"reply":{"error":{"description":"XMO_REQUEST_NO_ERR"},"value":"invalid \x8e byte"}}'
    invalid_byte = response_body.index(b"\x8e")
    decode_error = UnicodeDecodeError("utf-8", response_body, invalid_byte, invalid_byte + 1, "invalid start byte")

    response = AsyncMock()
    response.status = 200
    response.json = AsyncMock(side_effect=decode_error)
    response.read = AsyncMock(return_value=response_body)
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock(spec=ClientSession)
    session.post.return_value = response
    client = SagemcomClient(host="192.168.1.1", username="admin", password="admin", session=session)

    result = await client._SagemcomClient__post("http://192.168.1.1/ws", {})

    assert result["reply"]["value"] == "invalid � byte"


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
    """Test successful login with mocked session.

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
async def test_login_authentication_error(mock_session_factory, login_auth_error_response):
    """Test login raises AuthenticationException on XMO_AUTHENTICATION_ERR.

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
async def test_get_value_by_xpath_url_encoding(mock_session_factory, login_success_response, xpath_value_response):
    """Test XPath values are URL-encoded with safe characters preserved.

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
async def test_get_value_by_xpath_invalid_path(mock_session_factory, xpath_invalid_path_response):
    """Test XMO_INVALID_PATH_ERR raises UnknownPathException with error details."""
    mock_session = mock_session_factory([xpath_invalid_path_response])
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )

    with pytest.raises(UnknownPathException) as exc_info:
        await client.get_value_by_xpath("Device/Unsupported/Path")

    assert exc_info.value.args == (
        {
            "code": 16777242,
            "description": "XMO_INVALID_PATH_ERR",
        },
    )
    assert mock_session.post.call_count == 1


@pytest.mark.asyncio
async def test_login_with_preconfigured_fixture(mock_client_sha512):
    """Test login using pre-configured client fixture.

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


@pytest.mark.asyncio
async def test_get_value_by_xpath_suppresses_unknown_path(mock_session_factory, login_success_response, xpath_unknown_path_error_response):
    """Test that ignore_unknown_paths=True returns None for UnknownPathException."""
    mock_session = mock_session_factory([login_success_response, xpath_unknown_path_error_response])
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )
    await client.login()

    result = await client.get_value_by_xpath("Device/NonExistent", ignore_unknown_paths=True)

    assert result is None


@pytest.mark.asyncio
async def test_get_value_by_xpath_raises_unknown_path_when_not_suppressed(
    mock_session_factory, login_success_response, xpath_unknown_path_error_response
):
    """Test that ignore_unknown_paths=False (default) raises UnknownPathException."""
    mock_session = mock_session_factory([login_success_response, xpath_unknown_path_error_response])
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )
    await client.login()

    with pytest.raises(UnknownPathException):
        await client.get_value_by_xpath("Device/NonExistent")


@pytest.mark.asyncio
async def test_get_value_by_xpath_still_raises_auth_error_when_suppressed(
    mock_session_factory, login_success_response, login_auth_error_response
):
    """Test that ignore_unknown_paths=True still raises AuthenticationException."""
    # Auth errors trigger one re-login and retry (max_tries=2) before propagating.
    mock_session = mock_session_factory([login_success_response, login_auth_error_response] * 2)
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )
    await client.login()

    with pytest.raises(AuthenticationException):
        await client.get_value_by_xpath("Device/DeviceInfo", ignore_unknown_paths=True)

    assert mock_session.post.call_count == 4


@pytest.mark.asyncio
async def test_get_values_by_xpaths_suppresses_unknown_path_per_action(
    mock_session_factory, login_success_response, xpaths_mixed_errors_response
):
    """Suppressed unknown-path actions return None while other values are preserved."""
    mock_session = mock_session_factory([login_success_response, xpaths_mixed_errors_response])
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )
    await client.login()

    result = await client.get_values_by_xpaths(
        {
            "mac_address": "Device/DeviceInfo/MACAddress",
            "model_number": "Device/DeviceInfo/ModelNumber",
        },
        ignore_unknown_paths=True,
    )

    assert result["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert result["model_number"] is None


@pytest.mark.asyncio
async def test_get_values_by_xpaths_still_raises_auth_error_when_suppressed(
    mock_session_factory, login_success_response, login_auth_error_response
):
    """A suppressed call still raises AuthenticationException instead of swallowing it."""
    # Auth errors trigger one re-login and retry (max_tries=2) before propagating.
    mock_session = mock_session_factory([login_success_response, login_auth_error_response] * 2)
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )
    await client.login()

    with pytest.raises(AuthenticationException):
        await client.get_values_by_xpaths(
            {"mac_address": "Device/DeviceInfo/MACAddress"},
            ignore_unknown_paths=True,
        )

    assert mock_session.post.call_count == 4


@pytest.mark.asyncio
async def test_get_device_info_falls_back_when_aggregate_path_unknown(
    mock_session_factory,
    login_success_response,
    xpath_unknown_path_error_response,
    device_info_fallback_partial_response,
):
    """A device missing the aggregate DeviceInfo path still yields a DeviceInfo.

    The aggregate probe raises UnknownPathException, triggering the per-attribute
    fallback. There, the unknown ModelNumber is tolerated (returned as None) while
    the remaining attributes are populated.
    """
    mock_session = mock_session_factory(
        [
            login_success_response,
            xpath_unknown_path_error_response,
            device_info_fallback_partial_response,
        ]
    )
    client = SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )
    await client.login()

    info = await client.get_device_info()

    assert info.mac_address == "AA:BB:CC:DD:EE:FF"
    assert info.model_name is None  # ModelNumber was unknown, tolerated
    assert info.model_number == "F5364"
    assert info.serial_number == "SN123456789"
    assert info.software_version == "1.2.3"
    assert info.manufacturer == "Sagemcom"


def _reply(request_error: str, action_errors: list[str]) -> dict:
    """Build a JSON-req reply whose actions carry no values."""
    return {
        "reply": {
            "uid": 0,
            "id": 1,
            "error": {"code": 1, "description": request_error},
            "actions": [
                {"uid": i + 1, "id": i, "error": {"code": 1, "description": desc}, "callbacks": []} for i, desc in enumerate(action_errors)
            ],
            "events": [],
        }
    }


def _md5_client(session) -> SagemcomClient:
    return SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=session,
    )


@pytest.mark.asyncio
async def test_get_values_by_xpaths_ignores_invalid_path_per_action(
    mock_session_factory, login_success_response, xpaths_mixed_errors_response
):
    """XMO_INVALID_PATH_ERR is treated as a missing path, like XMO_UNKNOWN_PATH_ERR."""
    mixed_response = deepcopy(xpaths_mixed_errors_response)
    mixed_response["reply"]["actions"][1]["error"] = {"code": 16777242, "description": "XMO_INVALID_PATH_ERR"}
    client = _md5_client(mock_session_factory([login_success_response, mixed_response]))
    await client.login()

    result = await client.get_values_by_xpaths(
        {"mac_address": "Device/DeviceInfo/MACAddress", "model_number": "Device/DeviceInfo/ModelNumber"},
        ignore_unknown_paths=True,
    )

    assert result == {"mac_address": "AA:BB:CC:DD:EE:FF", "model_number": None}


@pytest.mark.parametrize("ignore_unknown_paths", [False, True])
@pytest.mark.asyncio
async def test_request_level_auth_error_is_not_masked_by_action_placeholder(
    mock_session_factory, login_success_response, ignore_unknown_paths
):
    """Request-level XMO_AUTHENTICATION_ERR raises, even when actions only report an unknown path."""
    auth_error = _reply("XMO_AUTHENTICATION_ERR", ["XMO_UNKNOWN_PATH_ERR"])
    mock_session = mock_session_factory([login_success_response, auth_error] * 2)
    client = _md5_client(mock_session)
    await client.login()

    with pytest.raises(AuthenticationException):
        await client.get_value_by_xpath("Device/DeviceInfo/ModelNumber", ignore_unknown_paths=ignore_unknown_paths)

    # Re-login and retry once, as for action-level authentication errors.
    assert mock_session.post.call_count == 4


@pytest.mark.asyncio
async def test_invalid_session_relogs_in_and_retries(
    mock_session_factory, login_success_response, login_invalid_session_response, xpath_value_response
):
    """An invalidated session is transient: log in again and retry the request (#520)."""
    mock_session = mock_session_factory(
        [login_success_response, login_invalid_session_response, login_success_response, xpath_value_response]
    )
    client = _md5_client(mock_session)
    await client.login()

    value = await client.get_value_by_xpath("Device/WiFi/Radios/Radio[@uid='1']/Status", ignore_unknown_paths=True)

    assert value == "UP"
    assert mock_session.post.call_count == 4


@pytest.mark.asyncio
async def test_invalid_session_propagates_after_retry(mock_session_factory, login_success_response, login_invalid_session_response):
    """A session that stays invalid surfaces as InvalidSessionException, not an auth failure."""
    mock_session = mock_session_factory([login_success_response, login_invalid_session_response] * 2)
    client = _md5_client(mock_session)
    await client.login()

    with pytest.raises(InvalidSessionException):
        await client.get_value_by_xpath("Device/DeviceInfo")


@pytest.mark.asyncio
async def test_set_value_by_xpath_still_raises_action_errors(mock_session_factory):
    """Requests other than getters keep raising action-level errors."""
    client = _md5_client(mock_session_factory([_reply("XMO_REQUEST_ACTION_ERR", ["XMO_NON_WRITABLE_PARAMETER_ERR"])]))

    with pytest.raises(NonWritableParameterException):
        await client.set_value_by_xpath("Device/DeviceInfo/ModelNumber", "x")


@pytest.mark.parametrize("request_error", ["XMO_REQUEST_ACTION_ERR", "XMO_LOGIN_RETRY_ERR"])
@pytest.mark.asyncio
async def test_login_raises_login_retry_error(mock_session_factory, request_error):
    """A locked login raises LoginRetryErrorException, whether reported per action or per request."""
    client = _md5_client(mock_session_factory([_reply(request_error, ["XMO_LOGIN_RETRY_ERR"])]))

    with pytest.raises(LoginRetryErrorException):
        await client.login()


@pytest.mark.asyncio
async def test_get_device_info_fallback_requires_mac_address(
    mock_session_factory,
    login_success_response,
    xpath_unknown_path_error_response,
    device_info_fallback_partial_response,
):
    """Missing optional attributes are tolerated, but the MAC address is not."""
    fallback_response = deepcopy(device_info_fallback_partial_response)
    fallback_response["reply"]["actions"][0]["error"] = {"code": 16777221, "description": "XMO_UNKNOWN_PATH_ERR"}
    fallback_response["reply"]["actions"][0]["callbacks"] = []
    client = _md5_client(mock_session_factory([login_success_response, xpath_unknown_path_error_response, fallback_response]))
    await client.login()

    with pytest.raises(UnknownPathException):
        await client.get_device_info()


@pytest.mark.parametrize("call", ["reboot", "run_speed_test"])
@pytest.mark.asyncio
async def test_non_getter_actions_raise_action_errors(mock_session_factory, call):
    """Reboot and speed test surface action-level errors instead of returning them."""
    client = _md5_client(mock_session_factory([_reply("XMO_REQUEST_ACTION_ERR", ["XMO_AUTHENTICATION_ERR"])]))

    with pytest.raises(AuthenticationException):
        await getattr(client, call)()
