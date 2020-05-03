# python-sagemcom-api (WIP)

Unofficial Python wrapper to interact with SagemCom F@st routers via internal API's. This package is utilizing async/await, thus Python 3.7+ is required.

## Features

- Get (connected) devices
- Get device information
- Reboot device

## Supported devices

The Sagemcom F@st series is in use by multiple cable companies, where some cable companies did rebrand the router. Examples are the b-box from Proximus, Home Hub from bell and the Smart Hub from BT.

| Router Model         | Provider(s)           | Authentication Method |
| -------------------- | --------------------- | --------------------- |
| Sagemcom F@st 3864   | Optus                 | sha512                |
| Sagemcom F@st 3865b  | Proximus (b-box3)     | md5                   |
| Sagemcom F@st 3890V3 | Delta / Zeelandnet    | md5                   |
| Sagemcom F@st 5250   | Bell (Home Hub 2000 ) | md5                   |
| Sagemcom F@st 5280   |                       | sha512                |
| Sagemcom F@st 5364   | BT ( Smart Hub)       | md5                   |
| Sagemcom F@st 5370e  | Telia                 | sha512                |
| Sagemcom F@st 5566   | Bell (Home Hub 3000)  | md5                   |
| Sagemcom F@st 5655V2 | MásMóvil              | md5                   |

_Other Sagemcom F@st router models could be supported, please create an issue if you have a device which doesn't work out of the box with this package._

## Installation

_This package has not been published on PyPi yet since it is a work in progress, clone this repository to get started._

```bash
pip install sagemcom-api
```

## Usage

Depending on the router model, Sagemcom is using different encryption methods for authentication, which can be found in [the table above](#supported-devices). This package supports MD5 and SHA512 encryption.

```python
import asyncio
from sagemcom_api import SagemcomClient, EncryptionMethod

async def main():
    # Choose EncryptionMethod.MD5 or EncryptionMethod.SHA512
    sagemcom = Sagemcom_Client('local ip address', 'username', 'password', EncryptionMethod.MD5)

    logged_in = await sagemcom.login()

    if logged_in:
        device_info = await sagemcom.get_device_info()
        print(device_info)

asyncio.run(main())
```

## TODO

- Auto login for the first request
- Add helper function to determine if the model is using MD5 or SHA512 encryption for authentication
- Add function to pass custom action
- Add helper function to parse output
- Document all functions

## Related

- [wuseman/SAGEMCOM-FAST-5370e-TELIA](https://github.com/wuseman/SAGEMCOM-FAST-5370e-TELIA)
- [insou22/optus-router-tools](https://github.com/insou22/optus-router-tools)
- [onegambler/bthomehub_client](https://github.com/onegambler/bthomehub_client)
