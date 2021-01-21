"""Client to communicate with Sagemcom F@st internal APIs."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import random
from types import TracebackType
from typing import Dict, List, Optional, Type

from aiohttp import ClientSession, ClientTimeout
import humps

from . import __version__
from .const import (
    API_ENDPOINT,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    XMO_ACCESS_RESTRICTION_ERR,
    XMO_AUTHENTICATION_ERR,
    XMO_NO_ERR,
    XMO_NON_WRITABLE_PARAMETER_ERR,
    XMO_REQUEST_ACTION_ERR,
    XMO_REQUEST_NO_ERR,
    XMO_UNKNOWN_PATH_ERR,
)
from .enums import EncryptionMethod
from .exceptions import (
    AccessRestrictionException,
    AuthenticationException,
    BadRequestException,
    LoginTimeoutException,
    NonWritableParameterException,
    UnauthorizedException,
    UnknownException,
    UnknownPathException,
)
from .models import Device, DeviceInfo, PortMapping


class SagemcomClient:
    """Client to communicate with the Sagemcom API."""

    def __init__(
        self,
        host,
        username,
        password,
        authentication_method=EncryptionMethod.UNKNOWN,
        session: ClientSession = None,
    ):
        """
        Create a SagemCom client.

        :param host: the host of your Sagemcom router
        :param username: the username for your Sagemcom router
        :param password: the password for your Sagemcom router
        :param authentication_method: the auth method of your Sagemcom router
        :param session: use a custom session, for example to configure the timeout
        """
        self.host = host
        self.username = username
        self.authentication_method = authentication_method
        self._password_hash = self.__generate_hash(password)

        self._current_nonce = None
        self._server_nonce = ""
        self._session_id = 0
        self._request_id = -1

        self.session = (
            session
            if session
            else ClientSession(
                headers={"User-Agent": f"{DEFAULT_USER_AGENT}/{__version__}"},
                timeout=ClientTimeout(DEFAULT_TIMEOUT),
            )
        )

    async def __aenter__(self) -> SagemcomClient:
        """TODO."""
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Close session on exit."""
        await self.close()

    async def close(self) -> None:
        """Close the websession."""
        await self.session.close()

    def __generate_nonce(self):
        """Generate pseudo random number (nonce) to avoid replay attacks."""
        self._current_nonce = math.floor(random.randrange(0, 1) * 500000)

    def __generate_request_id(self):
        """Generate sequential request ID."""
        self._request_id += 1

    def __generate_hash(self, value, authentication_method=None):
        """Hash value with selected encryption method and return HEX value."""
        auth_method = authentication_method or self.authentication_method

        bytes_object = bytes(value, encoding="utf-8")

        if auth_method == EncryptionMethod.MD5:
            return hashlib.md5(bytes_object).hexdigest()

        if auth_method == EncryptionMethod.SHA512:
            return hashlib.sha512(bytes_object).hexdigest()

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
            value = response["reply"]["actions"][index]["callbacks"][index][
                "parameters"
            ]
        except KeyError:
            value = None

        return value

    def __get_response_value(self, response, index=0):
        """Retrieve response value from value."""
        try:
            value = self.__get_response(response, index)["value"]
        except KeyError:
            value = None

        # Rewrite result to snake_case
        value = humps.decamelize(value)

        return value

    async def __api_request_async(self, actions, priority=False):
        """Build request to the internal JSON-req API."""
        # Auto login
        if self._server_nonce == "" and actions[0]["method"] != "logIn":
            await self.login()

        self.__generate_request_id()
        self.__generate_nonce()
        self.__generate_auth_key()

        api_host = f"http://{self.host}{API_ENDPOINT}"

        payload = {
            "request": {
                "id": self._request_id,
                "session-id": str(self._session_id),
                "priority": priority,
                "actions": actions,
                "cnonce": self._current_nonce,
                "auth-key": self._auth_key,
            }
        }

        async with self.session.post(
            api_host, data="req=" + json.dumps(payload, separators=(",", ":"))
        ) as response:

            if response.status == 400:
                result = await response.text()
                raise BadRequestException(result)

            if response.status != 200:
                result = await response.text()
                raise UnknownException(result)

            if response.status == 200:
                result = await response.json()
                error = self.__get_response_error(result)

                # No errors
                if (
                    error["description"] == XMO_REQUEST_NO_ERR
                    or error["description"] == "Ok"  # NOQA: W503
                ):
                    return result

                # Error in one of the actions
                if error["description"] == XMO_REQUEST_ACTION_ERR:

                    # TODO How to support multiple actions + error handling?
                    actions = result["reply"]["actions"]
                    for action in actions:
                        action_error = action["error"]
                        action_error_description = action_error["description"]

                        if action_error_description == XMO_NO_ERR:
                            continue

                        if action_error_description == XMO_AUTHENTICATION_ERR:
                            raise AuthenticationException(action_error)

                        if action_error_description == XMO_ACCESS_RESTRICTION_ERR:
                            raise AccessRestrictionException(action_error)

                        if action_error_description == XMO_NON_WRITABLE_PARAMETER_ERR:
                            raise NonWritableParameterException(action_error)

                        if action_error_description == XMO_UNKNOWN_PATH_ERR:
                            raise UnknownPathException(action_error)

                        raise UnknownException(action_error)

                return result

    async def login(self):
        """TODO."""
        actions = {
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
                "Request timed-out. This is mainly due to using the wrong encryption method."
            ) from exception

        data = self.__get_response(response)

        if data["id"] is not None and data["nonce"] is not None:
            self._session_id = data["id"]
            self._server_nonce = data["nonce"]
            return True
        else:
            raise UnauthorizedException(data)

    async def get_value_by_xpath(
        self, xpath: str, options: Optional[Dict] = {}
    ) -> Dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param options: optional options
        """
        actions = {"id": 0, "method": "getValue", "xpath": xpath, "options": options}

        response = await self.__api_request_async([actions], False)
        data = self.__get_response_value(response)

        return data

    async def set_value_by_xpath(
        self, xpath: str, value: str, options: Optional[Dict] = {}
    ) -> Dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param value: value
        :param options: optional options
        """
        actions = {
            "id": 0,
            "method": "setValue",
            "xpath": xpath,
            "parameters": {"value": str(value)},
            "options": options,
        }

        response = await self.__api_request_async([actions], False)
        print(response)

        return response

    async def get_device_info(self) -> DeviceInfo:
        """Retrieve information about Sagemcom F@st device."""
        data = await self.get_value_by_xpath("Device/DeviceInfo")

        return DeviceInfo(**data.get("device_info"))

    async def get_hosts(self, only_active: Optional[bool] = False) -> List[Device]:
        """Retrieve hosts connected to Sagemcom F@st device."""
        data = await self.get_value_by_xpath("Device/Hosts/Hosts")
        devices = [Device(**d) for d in data]

        if only_active:
            active_devices = [d for d in devices if d.active is True]
            return active_devices

        return devices

    async def get_port_mappings(self) -> List[PortMapping]:
        """Retrieve configured Port Mappings on Sagemcom F@st device."""
        data = await self.get_value_by_xpath("Device/NAT/PortMappings")
        port_mappings = [PortMapping(**p) for p in data]

        return port_mappings

    async def reboot(self):
        """Reboot Sagemcom F@st device."""
        action = {
            "method": "reboot",
            "xpath": "Device",
            "parameters": {"source": "GUI"},
        }

        response = await self.__api_request_async([action], False)
        data = self.__get_response_value(response)

        return data
