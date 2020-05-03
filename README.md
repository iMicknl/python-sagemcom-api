# python-sagemcom-api (WIP)

Python wrapper to interact with SagemCom F@st routers via internal API's. This package is utilizing async/await, thus required Pyton 3.7+.

## Features

- Get (connected) devices
- Get device information
- Reboot device

## Supported devices

The Sagemcom F@st series is in use by multiple cable companies, where some cable companies did rebrand the router. Examples are the b-box from Proximus and the Home Hub / Smart Hub from BT.

| Router Model         | Provider(s)               | Authentication Method |
| -------------------- | ------------------------- | --------------------- |
| Sagemcom F@st 3864   | Optus                     | sha512                |
| Sagemcom F@st 3865b  | Proximus (b-box3)         | md5                   |
| Sagemcom F@st 3890V3 | Delta / Zeelandnet        | md5                   |
| Sagemcom F@st 5280   |                           | sha512                |
| Sagemcom F@st 5364   | BT (Home Hub / Smart Hub) | md5                   |
| Sagemcom F@st 5370e  | Telia                     | sha512                |
| Sagemcom F@st 5655V2 | MásMóvil                  | md5                   |

_Other Sagemcom F@st router models could possibly be supported, please create an issue if you have a device which doesn't work out of the box with this package._

## Installation

_This package has not been published on PyPi yet since it is a work in progress, clone this repository to get started._

```bash
pip install sagemcom-api
```

## Usage

There are different authentication methods depending on your router model. This package supports MD5 and SHA512.

```python
import asyncio
from sagemcom_api.sagemcom_api import Sagemcom_Client

async def main():
    sagemcom = Sagemcom_Client('local ip address', 'username',  'password', AuthenticationMethods.MD5)

    logged_in = await sagemcom.login()

    if logged_in:
        device_info = await sagemcom.get_device_info()
        print(device_info)

asyncio.run(main())
```

## Related

- [wuseman/SAGEMCOM-FAST-5370e-TELIA](https://github.com/wuseman/SAGEMCOM-FAST-5370e-TELIA)
- [insou22/optus-router-tools](https://github.com/insou22/optus-router-tools)
- [onegambler/bthomehub_client](https://github.com/onegambler/bthomehub_client)
