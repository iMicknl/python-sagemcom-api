"""Client to communicate with Sagemcom F@st internal APIs."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import hashlib
import json
import math
import random
from types import TracebackType
from typing import Any
import urllib.parse

from aiohttp import (
    ClientConnectorError,
    ClientOSError,
    ClientSession,
    ClientTimeout,
    ContentTypeError,
    ServerDisconnectedError,
    TCPConnector,
)
import backoff
import humps

from .const import (
    API_ENDPOINT,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    UINT_MAX,
    XMO_ACCESS_RESTRICTION_ERR,
    XMO_AUTHENTICATION_ERR,
    XMO_INVALID_SESSION_ERR,
    XMO_LOGIN_RETRY_ERR,
    XMO_MAX_SESSION_COUNT_ERR,
    XMO_NO_ERR,
    XMO_NON_WRITABLE_PARAMETER_ERR,
    XMO_REQUEST_ACTION_ERR,
    XMO_REQUEST_NO_ERR,
    XMO_UNKNOWN_PATH_ERR,
)
from .enums import ApiMode, EncryptionMethod
from .exceptions import (
    AccessRestrictionException,
    AuthenticationException,
    BadRequestException,
    InvalidSessionException,
    LoginRetryErrorException,
    LoginTimeoutException,
    MaximumSessionCountException,
    NonWritableParameterException,
    UnauthorizedException,
    UnknownException,
    UnknownPathException,
    UnsupportedHostException,
)
from .models import Device, DeviceInfo, PortMapping


async def retry_login(invocation: Mapping[str, Any]) -> None:
    """Retry login via backoff if an exception occurs."""
    await invocation["args"][0].login()


# pylint: disable=too-many-instance-attributes
class SagemcomClient:
    """Client to communicate with the Sagemcom API."""

    _auth_key: str | None

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        authentication_method: EncryptionMethod | None = None,
        api_mode: ApiMode | str = ApiMode.AUTO,
        session: ClientSession | None = None,
        ssl: bool | None = False,
        verify_ssl: bool | None = True,
    ):
        """
        Create a SagemCom client.

        :param host: the host of your Sagemcom router
        :param username: the username for your Sagemcom router
        :param password: the password for your Sagemcom router
        :param authentication_method: the auth method of your Sagemcom router
        :param api_mode: one of auto, legacy or rest
        :param session: use a custom session, for example to configure the timeout
        """
        self.host = host
        self.username = username
        self.authentication_method = authentication_method
        self.api_mode = ApiMode(api_mode)
        self._active_api_mode: ApiMode = (
            self.api_mode if self.api_mode != ApiMode.AUTO else ApiMode.LEGACY
        )
        self.password = password
        self._current_nonce = None
        self._password_hash = self.__generate_hash(password)
        self.protocol = "https" if ssl else "http"

        self._server_nonce = ""
        self._session_id = 0
        self._request_id = -1

        self.session = (
            session
            if session
            else ClientSession(
                headers={"User-Agent": f"{DEFAULT_USER_AGENT}"},
                timeout=ClientTimeout(DEFAULT_TIMEOUT),
                connector=TCPConnector(
                    verify_ssl=verify_ssl if verify_ssl is not None else True
                ),
            )
        )

    @property
    def active_api_mode(self) -> ApiMode:
        """Return the API mode that is currently active."""
        return self._active_api_mode

    async def __aenter__(self) -> SagemcomClient:
        """TODO."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close session on exit."""
        await self.close()

    async def close(self) -> None:
        """Close the websession."""
        await self.session.close()

    def __generate_nonce(self, upper_limit=500000):
        """Generate pseudo random number (nonce) to avoid replay attacks."""
        self._current_nonce = math.floor(random.randrange(0, upper_limit))

    def __generate_request_id(self):
        """Generate sequential request ID."""
        self._request_id += 1

    def __generate_md5_nonce_hash(self):
        """Build MD5 with nonce hash token. UINT_MAX is hardcoded in the firmware."""

        def md5(input_string):
            return hashlib.md5(input_string.encode()).hexdigest()

        n = (
            self.__generate_nonce(UINT_MAX)
            if self._current_nonce is None
            else self._current_nonce
        )
        f = 0
        l_nonce = ""
        ha1 = md5(self.username + ":" + l_nonce + ":" + md5(self.password))

        return md5(ha1 + ":" + str(f) + ":" + str(n) + ":JSON:/cgi/json-req")

    def __generate_hash(self, value, authentication_method=None):
        """Hash value with selected encryption method and return HEX value."""
        auth_method = authentication_method or self.authentication_method

        bytes_object = bytes(value, encoding="utf-8")

        if auth_method == EncryptionMethod.MD5:
            return hashlib.md5(bytes_object).hexdigest()

        if auth_method == EncryptionMethod.SHA512:
            return hashlib.sha512(bytes_object).hexdigest()

        if auth_method == EncryptionMethod.MD5_NONCE:
            return self.__generate_md5_nonce_hash()

        return value

    def __get_credential_hash(self):
        """Build credential hash."""
        return self.__generate_hash(
            self.username + ":" + self._server_nonce + ":" + self._password_hash
        )

    def __generate_auth_key(self):
        """Build auth key."""
        credential_hash = self.__get_credential_hash()
        auth_string = f"{credential_hash}:{self._request_id}:{self._current_nonce}:JSON:{API_ENDPOINT}"
        self._auth_key = self.__generate_hash(auth_string)

    def __get_response_error(self, response):
        """Retrieve response error from result."""
        try:
            value = response["reply"]["error"]
        except KeyError:
            value = None

        return value

    def __get_response(self, response, index=0):
        """Retrieve response from result."""
        try:
            value = response["reply"]["actions"][index]["callbacks"][0]["parameters"]
        except KeyError:
            value = None

        return value

    def __get_response_value(self, response, index=0):
        """Retrieve response value from value."""
        try:
            value = self.__get_response(response, index)["value"]
        except KeyError:
            value = None
        except IndexError:
            value = None

        # Rewrite result to snake_case
        value = humps.decamelize(value)

        return value

    @backoff.on_exception(
        backoff.expo,
        (ClientConnectorError, ClientOSError, ServerDisconnectedError),
        max_tries=5,
    )
    # pylint: disable=too-many-branches
    async def __post(self, url, data):
        async with self.session.post(url, data=data) as response:
            if response.status == 400:
                result = await response.text()
                raise BadRequestException(result)

            if response.status == 404:
                result = await response.text()
                raise UnsupportedHostException(result)

            if response.status != 200:
                result = await response.text()
                raise UnknownException(result)

            result = await response.json()
            error = self.__get_response_error(result)

            # No errors
            if (
                error["description"] == XMO_REQUEST_NO_ERR
                or error["description"] == "Ok"  # NOQA: W503
            ):
                return result

            if error["description"] == XMO_INVALID_SESSION_ERR:
                self._session_id = 0
                self._server_nonce = ""
                self._request_id = -1
                raise InvalidSessionException(error)

            # Error in one of the actions
            if error["description"] == XMO_REQUEST_ACTION_ERR:
                # pylint:disable=fixme
                # TODO How to support multiple actions + error handling?
                actions = result["reply"]["actions"]
                for action in actions:
                    action_error = action["error"]
                    action_error_desc = action_error["description"]

                    if action_error_desc == XMO_NO_ERR:
                        continue

                    if action_error_desc == XMO_AUTHENTICATION_ERR:
                        raise AuthenticationException(action_error)

                    if action_error_desc == XMO_ACCESS_RESTRICTION_ERR:
                        raise AccessRestrictionException(action_error)

                    if action_error_desc == XMO_NON_WRITABLE_PARAMETER_ERR:
                        raise NonWritableParameterException(action_error)

                    if action_error_desc == XMO_UNKNOWN_PATH_ERR:
                        raise UnknownPathException(action_error)

                    if action_error_desc == XMO_MAX_SESSION_COUNT_ERR:
                        raise MaximumSessionCountException(action_error)

                    if action_error_desc == XMO_LOGIN_RETRY_ERR:
                        raise LoginRetryErrorException(action_error)

                    raise UnknownException(action_error)

            return result

    async def __api_request_async(self, actions, priority=False):
        """Build request to the internal JSON-req API."""
        self.__generate_request_id()
        self.__generate_nonce()
        self.__generate_auth_key()

        api_host = f"{self.protocol}://{self.host}{API_ENDPOINT}"

        payload = {
            "request": {
                "id": self._request_id,
                "session-id": int(self._session_id),
                "priority": priority,
                "actions": actions,
                "cnonce": self._current_nonce,
                "auth-key": self._auth_key,
            }
        }

        form_data = {"req": json.dumps(payload, separators=(",", ":"))}
        try:
            result = await self.__post(api_host, form_data)
            return result
        except (
            ClientConnectorError,
            ClientOSError,
            ServerDisconnectedError,
        ) as exception:
            raise ConnectionError(str(exception)) from exception

    async def __legacy_login(self):
        """Login to the legacy JSON-REQ API."""

        actions = {
            "id": 0,
            "method": "logIn",
            "parameters": {
                "user": self.username,
                "persistent": True,
                "session-options": {
                    "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
                    "language": "ident",
                    "context-flags": {"get-content-name": True, "local-time": True},
                    "capability-depth": 2,
                    "capability-flags": {
                        "name": True,
                        "default-value": False,
                        "restriction": True,
                        "description": False,
                    },
                    "time-format": "ISO_8601",
                    "write-only-string": "_XMO_WRITE_ONLY_",
                    "undefined-write-only-string": "_XMO_UNDEFINED_WRITE_ONLY_",
                },
            },
        }

        try:
            response = await self.__api_request_async([actions], True)
        except asyncio.TimeoutError as exception:
            raise LoginTimeoutException(
                "Login request timed-out. This could be caused by using the wrong encryption method, or using a (non) SSL connection."
            ) from exception

        data = self.__get_response(response)

        if data["id"] is not None and data["nonce"] is not None:
            self._session_id = data["id"]
            self._server_nonce = data["nonce"]
            return True

        raise UnauthorizedException(data)

    @backoff.on_exception(
        backoff.expo,
        (ClientConnectorError, ClientOSError, ServerDisconnectedError),
        max_tries=5,
    )
    async def __rest_request(
        self, method: str, endpoint: str, data: dict[str, Any] | None = None
    ):
        """Call the REST API using form-encoded payloads."""
        url = f"{self.protocol}://{self.host}{endpoint}"
        payload = urllib.parse.urlencode(data or {})
        request_headers = {"Content-Type": "application/x-www-form-urlencoded"}

        async with self.session.request(
            method, url, data=payload, headers=request_headers
        ) as response:
            if response.status in (200, 204):
                if response.status == 204:
                    return None
                try:
                    return await response.json()
                except (json.JSONDecodeError, ContentTypeError):
                    return await response.text()

            result = await response.text()
            if response.status in (401, 403):
                raise UnauthorizedException(result)

            if response.status == 404:
                raise UnsupportedHostException(result)

            if response.status == 400:
                raise AuthenticationException(result)

            raise UnknownException(result)

    async def __rest_login(self):
        """Login to routers exposing the newer REST API."""
        await self.__rest_request(
            "POST",
            "/api/v1/login",
            data={"login": self.username, "password": self.password},
        )
        return True

    def __should_fallback_to_rest(self, exception: Exception) -> bool:
        """Return True when legacy API failure indicates a REST-only router."""
        if isinstance(exception, UnsupportedHostException):
            return True

        if isinstance(exception, (UnknownException, BadRequestException)):
            content = str(exception).lower()
            return "service unavailable" in content or "<html" in content

        return False

    async def login(self):
        """Login to the router using configured API mode."""
        if self.api_mode == ApiMode.REST:
            self._active_api_mode = ApiMode.REST
            return await self.__rest_login()

        if self.api_mode == ApiMode.LEGACY:
            self._active_api_mode = ApiMode.LEGACY
            return await self.__legacy_login()

        # Auto-detect mode: try legacy first, then fall back to REST for newer firmwares.
        try:
            self._active_api_mode = ApiMode.LEGACY
            return await self.__legacy_login()
        except Exception as exception:  # pylint: disable=broad-except
            if not self.__should_fallback_to_rest(exception):
                raise

            self._active_api_mode = ApiMode.REST
            return await self.__rest_login()

    async def logout(self):
        """Log out of the Sagemcom F@st device."""
        if self._active_api_mode == ApiMode.REST:
            await self.__rest_request("POST", "/api/v1/logout")
        else:
            actions = {"id": 0, "method": "logOut"}
            await self.__api_request_async([actions], False)

        self._session_id = -1
        self._server_nonce = ""
        self._request_id = -1

    def __ensure_legacy_api(self):
        """Raise when a method is only available on legacy JSON-REQ API."""
        if self._active_api_mode == ApiMode.REST:
            raise NotImplementedError(
                "This method is not available with REST API mode. "
                "Use helper methods supported for REST firmware instead."
            )

    async def get_encryption_method(self):
        """Determine which encryption method to use for authentication and set it directly."""
        if self.api_mode == ApiMode.REST:
            return None

        for encryption_method in EncryptionMethod:
            try:
                self.authentication_method = encryption_method
                self._password_hash = self.__generate_hash(
                    self.password, encryption_method
                )

                await self.login()

                self._server_nonce = ""
                self._session_id = 0
                self._request_id = -1

                return encryption_method
            except (
                LoginTimeoutException,
                AuthenticationException,
                LoginRetryErrorException,
            ):
                pass

        return None

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_value_by_xpath(self, xpath: str, options: dict | None = None) -> dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param options: optional options
        """
        self.__ensure_legacy_api()

        actions = {
            "id": 0,
            "method": "getValue",
            "xpath": urllib.parse.quote(xpath, "/=[]'"),
            "options": options if options else {},
        }

        response = await self.__api_request_async([actions], False)
        data = self.__get_response_value(response)

        return data

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_values_by_xpaths(self, xpaths, options: dict | None = None) -> dict:
        """
        Retrieve raw values from router using XPath.

        :param xpaths: Dict of key to xpath expression
        :param options: optional options
        """
        self.__ensure_legacy_api()

        actions = [
            {
                "id": i,
                "method": "getValue",
                "xpath": urllib.parse.quote(xpath, "/=[]'"),
                "options": options if options else {},
            }
            for i, xpath in enumerate(xpaths.values())
        ]

        response = await self.__api_request_async(actions, False)
        values = [self.__get_response_value(response, i) for i in range(len(xpaths))]
        data = dict(zip(xpaths.keys(), values))

        return data

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def set_value_by_xpath(
        self, xpath: str, value: str, options: dict | None = None
    ) -> dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param value: value
        :param options: optional options
        """
        self.__ensure_legacy_api()

        actions = {
            "id": 0,
            "method": "setValue",
            "xpath": urllib.parse.quote(xpath, "/=[]'"),
            "parameters": {"value": str(value)},
            "options": options if options else {},
        }

        response = await self.__api_request_async([actions], False)

        return response

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_device_info(self) -> DeviceInfo:
        """Retrieve information about Sagemcom F@st device."""
        if self._active_api_mode == ApiMode.REST:
            data = await self.__rest_request("GET", "/api/v1/device")
            if not data or not isinstance(data, list):
                raise UnknownException("Invalid response from /api/v1/device")

            device = data[0].get("device", {})
            return DeviceInfo(
                mac_address=device.get("wan_mac_address"),
                serial_number=device.get("serialnumber"),
                model_name=device.get("modelname"),
                model_number=device.get("modelname"),
                product_class=device.get("modelname"),
                software_version=device.get("running", {}).get("version"),
                hardware_version=device.get("hardware_version"),
                manufacturer="Sagemcom",
                up_time=device.get("uptime"),
                first_use_date=device.get("firstusedate"),
                reboot_count=device.get("numberofboots"),
            )

        try:
            data = await self.get_value_by_xpath("Device/DeviceInfo")
            return DeviceInfo(**data["device_info"])
        except UnknownPathException:
            data = await self.get_values_by_xpaths(
                {
                    "mac_address": "Device/DeviceInfo/MACAddress",
                    "model_name": "Device/DeviceInfo/ModelNumber",
                    "model_number": "Device/DeviceInfo/ProductClass",
                    "product_class": "Device/DeviceInfo/ProductClass",
                    "serial_number": "Device/DeviceInfo/SerialNumber",
                    "software_version": "Device/DeviceInfo/SoftwareVersion",
                }
            )
            data["manufacturer"] = "Sagemcom"

        return DeviceInfo(**data)

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_hosts(self, only_active: bool | None = False) -> list[Device]:
        """Retrieve hosts connected to Sagemcom F@st device."""
        if self._active_api_mode == ApiMode.REST:
            data = await self.__rest_request("GET", "/api/v1/home")
            if not data or not isinstance(data, list):
                raise UnknownException("Invalid response from /api/v1/home")

            home = data[0]
            devices: list[Device] = []

            for entry in home.get("wirelessListDevice", []):
                devices.append(
                    Device(
                        uid=entry.get("id"),
                        phys_address=entry.get("macAddress"),
                        ip_address=entry.get("ipAddress"),
                        host_name=entry.get("hostname"),
                        user_host_name=entry.get("friendlyname"),
                        active=entry.get("active", True),
                        interface_type="wifi",
                        detected_device_type=entry.get("devicetype"),
                    )
                )

            for entry in home.get("ethernetListDevice", []):
                devices.append(
                    Device(
                        uid=entry.get("id"),
                        phys_address=entry.get("macAddress"),
                        ip_address=entry.get("ipAddress"),
                        host_name=entry.get("hostname"),
                        user_host_name=entry.get("friendlyname"),
                        active=entry.get("active", True),
                        interface_type="ethernet",
                        detected_device_type=entry.get("devicetype"),
                    )
                )

            if only_active:
                return [d for d in devices if d.active is True]

            return devices

        data = await self.get_value_by_xpath(
            "Device/Hosts/Hosts", options={"capability-flags": {"interface": True}}
        )
        devices = [Device(**d) for d in data]

        if only_active:
            active_devices = [d for d in devices if d.active is True]
            return active_devices

        return devices

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_port_mappings(self) -> list[PortMapping]:
        """Retrieve configured Port Mappings on Sagemcom F@st device."""
        self.__ensure_legacy_api()
        data = await self.get_value_by_xpath("Device/NAT/PortMappings")
        port_mappings = [PortMapping(**p) for p in data]

        return port_mappings

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def reboot(self):
        """Reboot Sagemcom F@st device."""
        self.__ensure_legacy_api()
        action = {
            "id": 0,
            "method": "reboot",
            "xpath": "Device",
            "parameters": {"source": "GUI"},
        }

        response = await self.__api_request_async([action], False)
        data = self.__get_response_value(response)

        return data
