## Troubleshooting `SSLV3_ALERT_HANDSHAKE_FAILURE`

A `SSLV3_ALERT_HANDSHAKE_FAILURE` error when connecting to the router indicates that there is a mismatch with the cipher being used in the SSL connection (see [here](https://stackoverflow.com/a/73254780/487356)).

Running `openssl s_client -connect <router-ip>:<ssl-port>` on the router shows what cipher can be used. In the case of a "Sunrise Internet Box" it was `AES256-GCM-SHA384`.

The following code snippet shows how to set up a `SagemcomClient` configured to use that specific cipher (and not validating the router's certificate):

```
async def main() -> None:
    sslcontext = ssl._create_unverified_context()
    sslcontext.set_ciphers("AES256-GCM-SHA384")

    session = ClientSession(
        headers={"User-Agent": f"{DEFAULT_USER_AGENT}"},
        timeout=ClientTimeout(DEFAULT_TIMEOUT),
        connector=TCPConnector(
            ssl_context=sslcontext
        )
    )
    async with SagemcomClient(HOST, USERNAME, PASSWORD, ENCRYPTION_METHOD, session=session) as client:
```
