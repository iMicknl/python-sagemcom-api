# python-sagemcom-api

(Unofficial) Python wrapper to interact with SagemCom F@st routers via internal API's. This package is utilizing async/await, thus Python 3.7+ is required.

## Features

- Get (connected) devices
- Get router information
- Reboot router

## Supported devices

The Sagemcom F@st series is in use by multiple cable companies, where some cable companies did rebrand the router. Examples are the b-box from Proximus, Home Hub from bell and the Smart Hub from BT.

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

> Contributions welcome. If you router model is supported by this package, but not in the list above, please create [an issue](https://github.com/iMicknl/python-sagemcom-api/issues/new) or pull request.

## Installation

_This package has not been published on PyPi yet since it is a work in progress._

```bash
pip install sagemcom_api@git+https://github.com/iMicknl/python-sagemcom-api
```

## Usage

Depending on the router model, Sagemcom is using different encryption methods for authentication, which can be found in [the table above](#supported-devices). This package supports MD5 and SHA512 encryption. You don't need to login before every function call, the package will login automatically if necessary.

```python
import asyncio
from sagemcom_api import SagemcomClient, EncryptionMethod

async def main():
    # Choose EncryptionMethod.MD5, EncryptionMethod.SHA512 or EncryptionMethod.Unknown
    sagemcom = SagemcomClient('local ip address', 'username', 'password', EncryptionMethod.MD5)

    try:
        device_info = await sagemcom.get_device_info()
        print(device_info)
    except:
        print('error')

asyncio.run(main())
```

## TODO

- Auto login for the first request
- Add proper exceptions + handling
- Add helper function to determine if the model is using MD5 or SHA512 encryption for authentication
- Add function to pass custom action
- Add helper function to parse output
- Document all functions

## Functions

- ```login()```
- ```get_device_info(raw=False)```
- ```get_port_mappings()```
- ```get_hosts()```
- ```reboot()```

## Advanced

### Determine EncryptionMethod

### Exceptions

### Get raw response

## Inspired by

- [wuseman/SAGEMCOM-FAST-5370e-TELIA](https://github.com/wuseman/SAGEMCOM-FAST-5370e-TELIA)
- [insou22/optus-router-tools](https://github.com/insou22/optus-router-tools)
- [onegambler/bthomehub_client](https://github.com/onegambler/bthomehub_client)
