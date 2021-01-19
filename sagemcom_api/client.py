"""Client to communicate with Sagemcom F@st internal APIs."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import random
from types import TracebackType
from typing import Optional, Type

import humps
from aiohttp import ClientSession, ClientTimeout

from .const import XMO_REQUEST_ACTION_ERR, XMO_REQUEST_NO_ERR
from .enums import EncryptionMethod
from .exceptions import (
    BadRequestException,
    TimeoutException,
    UnauthorizedException,
    UnknownException,
)
from .models import Device, DeviceInfo


class SagemcomClient:
    """Client to communicate with the Sagemcom API."""

    def __init__(
        self,
        host,
        username,
        password,
        authentication_method=EncryptionMethod.UNKNOWN,
        session: ClientSession = None,
        timeout: int = 7,
    ):
        """
        Create a SagemCom client.

        :param host: the host of your Sagemcom router
        :param username: the username for your Sagemcom router
        :param password: the password for your Sagemcom router
        :param authentication_method: the auth method of your Sagemcom router
        """
        self.host = host
        self.username = username
        self.authentication_method = authentication_method
        self._password_hash = self.__generate_hash(password)

        self._current_nonce = None
        self._server_nonce = ""
        self._session_id = 0
        self._request_id = -1
        self.session = session if session else ClientSession()
        self.timeout = timeout

    async def __aenter__(self) -> SagemcomClient:
        """TODO."""
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """TODO."""
        await self.close()

    async def close(self) -> None:
        """Close the session."""
        await self.session.close()

    def __generate_nonce(self):
        """Generate pseudo random number (nonce) to avoid replay attacks."""
        self._current_nonce = math.floor(random.randrange(0, 1) * 500000)

    def __generate_request_id(self):
        """Generate sequential request ID."""
        self._request_id += 1

    def __generate_hash(self, value):
        """Hash value with MD5 or SHA12 and return HEX."""
        bytes_object = bytes(value, encoding="utf-8")

        if self.authentication_method == EncryptionMethod.MD5:
            return hashlib.md5(bytes_object).hexdigest()

        if self.authentication_method == EncryptionMethod.SHA512:
            return hashlib.sha512(bytes_object).hexdigest()

        return value

    def __get_credential_hash(self):
        """Build credential hash."""
        return self.__generate_hash(
            self.username + ":" + self._server_nonce + ":" + self._password_hash
        )

    def __generate_auth_key(self):
        """Build auth key."""  # noqa: E501
        credential_hash = self.__get_credential_hash()
        auth_string = f"{credential_hash}:{self._request_id}:{self._current_nonce}:JSON:/cgi/json-req"
        self._auth_key = self.__generate_hash(auth_string)

    def __get_response_error(self, response):
        """TODO."""
        try:
            value = response["reply"]["error"]
        except KeyError:
            value = None

        return value

    def __get_response(self, response, index=0):
        """TODO."""
        try:
            value = response["reply"]["actions"][index]["callbacks"][index][
                "parameters"
            ]
        except KeyError:
            value = None

        return value

    def __get_response_value(self, response, index=0):
        """TODO."""
        try:
            value = self.__get_response(response, index)["value"]
        except KeyError:
            value = None

        return value

    async def __api_request_async(self, actions, priority=False):
        """Build request to the internal JSON-req API."""
        # Auto login
        if self._server_nonce == "" and actions[0]["method"] != "logIn":
            await self.login()

        self.__generate_request_id()
        self.__generate_nonce()
        self.__generate_auth_key()

        api_host = f"http://{self.host}/cgi/json-req"

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

        timeout = ClientTimeout(total=self.timeout)

        try:
            async with ClientSession(timeout=timeout) as session:
                async with session.post(
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

                        if error["description"] != XMO_REQUEST_NO_ERR:
                            if error["description"] == XMO_REQUEST_ACTION_ERR:
                                raise UnauthorizedException(error)

                            raise UnknownException(error)

                        return result

        except asyncio.TimeoutError as exception:
            raise TimeoutException from exception

    async def login(self):
        """TODO."""
        actions = {
            "method": "logIn",
            "parameters": {
                "user": self.username,
                "persistent": "true",
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

        response = await self.__api_request_async([actions], True)
        data = self.__get_response(response)

        if data["id"] is not None and data["nonce"] is not None:
            self._session_id = data["id"]
            self._server_nonce = data["nonce"]
            return True
        else:
            raise UnauthorizedException

    async def get_device_info(self, raw=False):
        """TODO."""
        actions = {"id": 0, "method": "getValue", "xpath": "Device/DeviceInfo"}

        response = await self.__api_request_async([actions], False)
        data = self.__get_response_value(response)
        data = humps.decamelize(data)  # TODO. move up the chain

        if raw:
            return data

        return DeviceInfo(**data.get("device_info"))

    async def get_port_mappings(self, raw=False):
        """TODO."""
        actions = {"id": 0, "method": "getValue", "xpath": "Device/NAT/PortMappings"}

        response = await self.__api_request_async([actions], False)
        data = self.__get_response_value(response)

        if raw:
            return data

        return data

    async def get_hosts(self, raw=False):
        """TODO."""
        actions = {
            "id": 0,
            "method": "getValue",
            "xpath": "Device/Hosts/Hosts",
            "options": {
                "capability-flags": {
                    "interface": True,
                }
            },
        }

        response = await self.__api_request_async([actions], False)
        data = self.__get_response_value(response)
        data = humps.decamelize(data)

        if raw:
            return data

        devices = [Device(**d) for d in data]

        return devices

    async def reboot(self):
        """TODO."""
        actions = {
            "method": "reboot",
            "xpath": "Device",
            "parameters": {"source": "GUI"},
        }

        response = await self.__api_request_async([actions], False)
        data = self.__get_response_value(response)

        return data

    async def get_ipv6_prefix_lan(self):
        """TODO."""
        actions = {
            "id": 0,
            "method": "getValue",
            "xpath": "Device/Managers/Network/IPAddressInformations/IPv6/PrefixLan",
            "options": {
                "capability-flags": {
                    "interface": True,
                }
            },
        }
        response = await self.__api_request_async([actions], False)
        data = self.__get_response_value(response)

        return data
