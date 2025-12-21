"""Shared pytest fixtures for Sagemcom API client tests."""

# pylint: disable=redefined-outer-name,duplicate-code

import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientSession
import pytest

from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import EncryptionMethod

# Fixture directory path
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(filename: str) -> Dict[str, Any]:
    """
    Load a JSON fixture file.

    :param filename: Name of the fixture file (e.g., 'login_success.json')
    :return: Parsed JSON data as dict
    """
    fixture_path = FIXTURES_DIR / filename
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def login_success_response() -> Dict[str, Any]:
    """Mock response for successful login."""
    return load_fixture("login_success.json")


@pytest.fixture
def login_auth_error_response() -> Dict[str, Any]:
    """Mock response for authentication error."""
    return load_fixture("login_auth_error.json")


@pytest.fixture
def login_invalid_session_response() -> Dict[str, Any]:
    """Mock response for invalid session error."""
    return load_fixture("login_invalid_session.json")


@pytest.fixture
def device_info_response() -> Dict[str, Any]:
    """Mock response for device info query."""
    return load_fixture("device_info.json")


@pytest.fixture
def hosts_response() -> Dict[str, Any]:
    """Mock response for hosts query."""
    return load_fixture("hosts.json")


@pytest.fixture
def xpath_value_response() -> Dict[str, Any]:
    """Mock response for generic XPath getValue."""
    return load_fixture("xpath_value.json")


@pytest.fixture
def mock_session_factory():
    """
    Factory fixture for creating mock aiohttp ClientSession.

    Returns a factory function that creates a mock session with configurable responses.
    Mock responses are consumed in sequence (first call gets first response, etc.).

    Usage:
        mock_session = mock_session_factory([response1, response2])
        # First POST call returns response1, second returns response2

    :return: Factory function that takes list of response dicts
    """

    def _create_mock_session(responses: List[Dict[str, Any]]) -> ClientSession:
        """
        Create a mock ClientSession with specified responses.

        :param responses: List of response dictionaries to return in sequence
        :return: Mock ClientSession
        """
        mock_session = MagicMock(spec=ClientSession)

        # Create async context manager mock for session.post()
        mock_post = MagicMock()
        mock_session.post = mock_post

        # Create response mocks for each configured response
        mock_responses = []
        for response_data in responses:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=response_data)
            mock_response.text = AsyncMock(return_value=json.dumps(response_data))
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            mock_responses.append(mock_response)

        # Configure post() to return responses in sequence
        if len(mock_responses) == 1:
            mock_post.return_value = mock_responses[0]
        else:
            mock_post.side_effect = mock_responses

        # Mock close method
        mock_session.close = AsyncMock()

        return mock_session

    return _create_mock_session


@pytest.fixture
def mock_client_md5(mock_session_factory, login_success_response):
    """
    Create a SagemcomClient with MD5 encryption and mocked session.

    Pre-configured with successful login response.

    :return: SagemcomClient instance
    """
    mock_session = mock_session_factory([login_success_response])
    return SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5,
        session=mock_session,
    )


@pytest.fixture
def mock_client_sha512(mock_session_factory, login_success_response):
    """
    Create a SagemcomClient with SHA512 encryption and mocked session.

    Pre-configured with successful login response.

    :return: SagemcomClient instance
    """
    mock_session = mock_session_factory([login_success_response])
    return SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.SHA512,
        session=mock_session,
    )


@pytest.fixture
def mock_client_md5_nonce(mock_session_factory, login_success_response):
    """
    Create a SagemcomClient with MD5_NONCE encryption and mocked session.

    Pre-configured with successful login response.

    :return: SagemcomClient instance
    """
    mock_session = mock_session_factory([login_success_response])
    return SagemcomClient(
        host="192.168.1.1",
        username="admin",
        password="admin",
        authentication_method=EncryptionMethod.MD5_NONCE,
        session=mock_session,
    )
