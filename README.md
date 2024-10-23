# Sagemcom API Client in Python

(Unofficial) async Python client to interact with Sagemcom F@st routers via internal API's. This client offers helper functions to retrieve common used functions, but also offers functionality to do custom requests via XPATH notation.

Python 3.9+ required.

## Features

- Retrieve detailed information of your Sagemcom F@st device
- Retrieve connected devices (wifi and ethernet)
- Reboot Sagemcom F@st device
- Retrieve and set all values of your Sagemcom F@st device

## Supported devices

The Sagemcom F@st series is used by multiple cable companies, where some cable companies did rebrand the router. Examples are the b-box from Proximus, Home Hub from bell and the Smart Hub from BT.

| Router Model                 | Provider(s)                | Authentication Method | Comments                      |
| ---------------------------- | -------------------------- | --------------------- | ----------------------------- |
| Sagemcom F@st 3864           | Optus                      | sha512                | username: guest, password: "" |
| Sagemcom F@st 3865b          | Proximus (b-box3)          | md5                   |                               |
| Sagemcom F@st 3890V3         | Delta / Zeelandnet         | sha512                |                               |
| Sagemcom F@st 3890V3         | DNA (DNA Mesh Wifi F-3890) | sha512                | username: admin               |
| Sagemcom F@st 3896           | Ziggo<sup>*</sup>          | sha512                | username: admin               |
| Sagemcom F@st 4360Air        | KPN                        | md5                   |                               |
| Sagemcom F@st 4353           | Belong Gateway             | md5                   | username: admin, password: "" |
| Sagemcom F@st 5250           | Bell (Home Hub 2000)       | md5                   | username: guest, password: "" |
| Sagemcom F@st 5280           |                            | sha512                |                               |
| Sagemcom F@st 5290 / FWR226e | Frontier                   | md5                   | username: admin               |
| Sagemcom F@st 5359           | KPN (Box 12)               | sha512                | username: admin               |
| Sagemcom F@st 5364           | BT (Smart Hub)             | md5                   | username: guest, password: "" |
| SagemCom F@st 5366SD         | Eir F3000                  | md5                   |                               |
| Sagemcom F@st 5370e          | Telia                      | sha512                |                               |
| Sagemcom F@st 5380           | TDC                        | md5                   |                               |
| Sagemcom F@st 5566           | Bell (Home Hub 3000)       | md5                   | username: guest, password: "" |
| Sagemcom F@st 5688T          | Salt (FibreBox_X6)         | sha512                | username: admin               |
| Sagemcom F@st 5689           | Bell (Home Hub 4000)       | md5                   | username: admin, password: "" |
| Sagemcom F@st 5689E          | Bell (Giga Hub)            | sha512                | username: admin, password: "" |
| Sagemcom F@st 5690           | Bell (Giga Hub)            | sha512                | username: admin, password: "" |
| Sagemcom F@st 5655V2         | MásMóvil                   | md5                   |                               |
| Sagemcom F@st 5657IL         |                            | md5                   |                               |
| Speedport Pro                | Telekom                    | md5                   | username: admin               |

<sup>*</sup> The firmware provided on the Sagemcom F@st 3896 router from Ziggo does not support the endpoint used in this library. [sagemcom-f3896lg-zg-api](https://github.com/mgyucht/sagemcom-f3896lg-zg-api) provides an API client suitable for Ziggo's firmware.

> Contributions welcome. If you router model is supported by this package, but not in the list above, please create [an issue](https://github.com/iMicknl/python-sagemcom-api/issues/new) or pull request.

## Installation

```bash
pip install sagemcom_api
```

## Getting Started

Depending on the router model, Sagemcom is using different encryption methods for authentication, which can be found in [the table above](#supported-devices). This package supports MD5 and SHA512 encryption. If you receive a `LoginTimeoutException`, you will probably need to use another encryption type.

The following script can be used as a quickstart.

```python
import asyncio
from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import EncryptionMethod
from sagemcom_api.exceptions import NonWritableParameterException

HOST = ""
USERNAME = ""
PASSWORD = ""
ENCRYPTION_METHOD = EncryptionMethod.SHA512 # or EncryptionMethod.MD5
VALIDATE_SSL_CERT = True

async def main() -> None:
    async with SagemcomClient(HOST, USERNAME, PASSWORD, ENCRYPTION_METHOD, verify_ssl=VALIDATE_SSL_CERT) as client:
        try:
            await client.login()
        except Exception as exception:  # pylint: disable=broad-except
            print(exception)
            return

        # Print device information of Sagemcom F@st router
        device_info = await client.get_device_info()
        print(f"{device_info.id} {device_info.model_name}")

        # Print connected devices
        devices = await client.get_hosts()

        for device in devices:
            if device.active:
                print(f"{device.id} - {device.name}")

        # Retrieve values via XPath notation, output is a dict
        custom_command_output = await client.get_value_by_xpath("Device/UserInterface/AdvancedMode")
        print(custom_command_output)

        # Set value via XPath notation and catch specific errors
        try:
            custom_command_output = await client.set_value_by_xpath("Device/UserInterface/AdvancedMode", "true")
        except NonWritableParameterException as exception:  # pylint: disable=broad-except
            print("Not allowed to set AdvancedMode parameter on your device.")
            return

        print(custom_command_output)

asyncio.run(main())
```

## Functions

- `login()`
- `get_device_info()`
- `get_hosts()`
- `get_port_mappings()`
- `reboot()`
- `get_value_by_xpath(xpath)`
- `set_value_by_xpath(xpath, value)`

## Advanced

### Determine the EncryptionMethod

If you are not sure which encryption method to use, you can leave it empty or pass `None` and use `get_encryption_method` to determine the encryption method.

`get_encryption_method` will return an `EncryptionMethod` when a match is found. Best would be to use this function only during your initial investigation.

This function will throw a `LoginTimeoutException` when no match is found, since this is still a HTTP Time Out. This could caused by the wrong encryption method, but also by trying to connect to an inaccessible host.

### Handle exceptions

Some functions may cause an error when an attempt is made to execute it. These exceptions are thrown by the client and need to be [handled in your Python program](https://docs.python.org/3/tutorial/errors.html#handling-exceptions). Best practice is to catch some specific exceptions and handle them gracefully.

```python
from sagemcom_api.exceptions import *

try:
    await client.set_value_by_xpath("Device/UserInterface/AdvancedMode", "true")
except NonWritableParameterException as exception:
    print("You don't have rights to write to this parameter.")
except UnknownPathException as exception:
    print("The xpath does not exist.")
```

### Run your custom commands

Not all values can be retrieved by helper functions in this client implementation. By using XPath, you are able to return all values via the API. The result will be a dict response, or [an exception](#handle-exceptions) when the attempt was not successful.

```python
try:
    result = await client.get_value_by_xpath("Device/DeviceSummary")
except Exception as exception:
    print(exception)
```

### Use your own aiohttp ClientSession

> ClientSession is the heart and the main entry point for all client API operations. The session contains a cookie storage and connection pool, thus cookies and connections are shared between HTTP requests sent by the same session.

In order to change settings like the time-out, it is possible to pass your custom [aiohttp ClientSession](https://docs.aiohttp.org/en/stable/client_advanced.html).

```python
from aiohttp import ClientSession, ClientTimeout

session = ClientSession(timeout=ClientTimeout(100))
client = SagemcomClient(session=session)
```

### Debugging

- Unable to login (XMO_AUTHENTICATION_ERR)

See [advanced instructions for debugging](docs/debugging.md) common issues.

## Inspired by

- [wuseman/SAGEMCOM-FAST-5370e-TELIA](https://github.com/wuseman/SAGEMCOM-FAST-5370e-TELIA)
- [insou22/optus-router-tools](https://github.com/insou22/optus-router-tools)
- [onegambler/bthomehub_client](https://github.com/onegambler/bthomehub_client)
