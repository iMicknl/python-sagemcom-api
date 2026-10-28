"""Tests for transport retries on actions that must not run twice."""

import asyncio
import json
import urllib.parse
from unittest.mock import AsyncMock

import pytest
from aiohttp import ClientSession, ClientTimeout

from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import EncryptionMethod

OK_REPLY = {
    "reply": {
        "uid": 0,
        "id": 0,
        "error": {"code": 16777216, "description": "XMO_REQUEST_NO_ERR"},
        "actions": [
            {
                "uid": 1,
                "id": 0,
                "error": {"code": 16777238, "description": "XMO_NO_ERR"},
                "callbacks": [
                    {"uid": 1, "result": {"code": 16777238, "description": "XMO_NO_ERR"}, "xpath": "Device", "parameters": {"value": "ok"}}
                ],
            }
        ],
        "events": [],
    }
}


class FlakyRouter:
    """Raw TCP server that accepts each request, then drops the first `drops` connections without answering."""

    def __init__(self, drops: int):
        """Drop the first `drops` connections after reading the request."""
        self.drops = drops
        self.methods: list[str] = []
        self.server: asyncio.Server | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        length = next(int(line.split(b":")[1]) for line in head.split(b"\r\n") if line.lower().startswith(b"content-length"))
        body = await reader.readexactly(length)
        request = json.loads(urllib.parse.parse_qs(body.decode())["req"][0])["request"]
        self.methods.extend(action["method"] for action in request["actions"])

        if len(self.methods) <= self.drops:
            writer.transport.abort()  # The router acted on the request, then went away without replying.
            return

        payload = json.dumps(OK_REPLY).encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(payload), payload))
        await writer.drain()
        writer.close()

    async def __aenter__(self) -> str:
        """Start the server and return its host:port."""
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]
        return f"127.0.0.1:{port}"

    async def __aexit__(self, *exc) -> None:
        """Stop the server."""
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize(("call", "method"), [("reboot", "reboot"), ("run_speed_test", "speedTestClient")])
async def test_non_idempotent_action_is_not_resent_after_disconnect(call, method):
    """A reboot (or speed test) that reached the router must not be sent again when the connection drops."""
    router = FlakyRouter(drops=99)
    async with router as host, ClientSession(timeout=ClientTimeout(total=10)) as session:
        client = SagemcomClient(host, "admin", "admin", EncryptionMethod.MD5, session=session)

        with pytest.raises(ConnectionError):
            await getattr(client, call)()

    assert router.methods == [method]


@pytest.mark.asyncio
async def test_read_is_still_retried_after_disconnect(monkeypatch):
    """Reads are safe to repeat, so a dropped connection is still retried."""
    monkeypatch.setattr(asyncio, "sleep", AsyncMock())  # skip the backoff delay
    router = FlakyRouter(drops=1)
    async with router as host, ClientSession(timeout=ClientTimeout(total=10)) as session:
        client = SagemcomClient(host, "admin", "admin", EncryptionMethod.MD5, session=session)

        value = await client.get_value_by_xpath("Device")

    assert value == "ok"
    assert router.methods == ["getValue", "getValue"]
