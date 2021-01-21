# python-sagemcom-api

(Unofficial) Python client to interact with SagemCom F@st routers via internal API's. This client offers helper functions to retrieve common used functions, but also offers functionality to do custom requests via XPATH notation.

Python 3.7+ required.

## Features

- Retrieve detailed information of Sagemcom F@st device
- Retrieve connected devices (wifi and ethernet)
- Reboot Sagemcom F@st device

## Supported devices

The Sagemcom F@st series is used by multiple cable companies, where some cable companies did rebrand the router. Examples are the b-box from Proximus, Home Hub from bell and the Smart Hub from BT.

| Router Model         | Provider(s)          | Authentication Method |
| -------------------- | -------------------- | --------------------- |
| Sagemcom F@st 3864   | Optus                | sha512                |
| Sagemcom F@st 3865b  | Proximus (b-box3)    | md5                   |
| Sagemcom F@st 3890V3 | Delta / Zeelandnet   | md5                   |
| Sagemcom F@st 5250   | Bell (Home Hub 2000) | md5                   |
| Sagemcom F@st 5280   |                      | sha512                |
| Sagemcom F@st 5364   | BT (Smart Hub)       | md5                   |
| Sagemcom F@st 5370e  | Telia                | sha512                |
| Sagemcom F@st 5566   | Bell (Home Hub 3000) | md5                   |
| Sagemcom F@st 5655V2 | MásMóvil             | md5                   |
| Speedport Pro        | Telekom              | md5                   |

> Contributions welcome. If you router model is supported by this package, but not in the list above, please create [an issue](https://github.com/iMicknl/python-sagemcom-api/issues/new) or pull request.

## Installation

_This package has not been published on PyPi yet since it is a work in progress._

```bash
pip install sagemcom_api@git+https://github.com/iMicknl/python-sagemcom-api@v1.0.0
```

## Usage

Depending on the router model, Sagemcom is using different encryption methods for authentication, which can be found in [the table above](#supported-devices). This package supports MD5 and SHA512 encryption. You don't need to login before every function call, the package will login automatically if necessary.

```python
import asyncio
from sagemcom_api.enums import EncryptionMethod
from sagemcom_api.client import SagemcomClient

HOST = ""
USERNAME = ""
PASSWORD = ""
ENCRYPTION_METHOD = EncryptionMethod.MD5 # or EncryptionMethod.SHA512

async def main() -> None:
    async with SagemcomClient(HOST, USERNAME, PASSWORD, ENCRYPTION_METHOD) as client:
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

        # Run custom command, output is a dict
        custom_command_output = await client.get_value_by_xpath("Device/Managers/Network/IPAddressInformations/IPv6/PrefixLan")
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
TODO

### Handle exceptions
Some functions may cause an error when an attempt is made to execute it. These exceptions are thrown by the client and need to be [handled in your Python program](https://docs.python.org/3/tutorial/errors.html#handling-exceptions). Best practice is to handle the exceptions and 

```python
from sagemcom_api.exceptions import *

try:
    await client.set_value_by_xpath("Device/UserInterface/AdvancedMode", "true")
except NonWritableParameterException as exception:
    print("You don't have rights to write to this parameter.")
except UnknownPathException as exception:
    print("The xptah does not exist.")
```

### Run your custom commands

Not all values can be retrieved by helper functions in this client implementation. By using XPath, you are able to return all values via the API. The result will be a dict response, or a BadRequestException when the XPath is not available.

```python
from sagemcom_api.exceptions import BadRequestException

try:
    result = await client.get_value_by_xpath("Device/DeviceSummary")
except BadRequestException as exception:
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


## Inspired by

- [wuseman/SAGEMCOM-FAST-5370e-TELIA](https://github.com/wuseman/SAGEMCOM-FAST-5370e-TELIA)
- [insou22/optus-router-tools](https://github.com/insou22/optus-router-tools)
- [onegambler/bthomehub_client](https://github.com/onegambler/bthomehub_client)
