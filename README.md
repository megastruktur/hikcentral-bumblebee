# hikcentral_bumblebee

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Bumblebee API client for HikCentral Pro v2.x (OverSea_Pro).

Pure-Python client for the undocumented **Bumblebee** web API of legacy
HikCentral Professional v2.x (OverSea_Pro) installations: login with session
key derivation, resource discovery (areas, doors, access controllers, cameras,
video intercoms), door status, and remote door actions (open / lock / remain
unlocked / remain locked).

## Installation

```bash
pip install -e .
```

Requires Python 3.11+, [httpx](https://www.python-httpx.org/) and
[pycryptodome](https://www.pycryptodome.org/).

## Usage

```python
from hikcentral_bumblebee import BumblebeeClient

cli = BumblebeeClient("https://your-hikcentral-host:443", "username", "password")
cli.login()

areas = cli.get_areas()
doors = cli.get_door_elements()
door = cli.get_door("996")
print(door.name, door.lock_state)

# Door actions: 1=open, 2=lock, 3=remain_unlocked, 4=remain_locked
cli.door_action("996", action=1)
```

## Protocol notes

Authentication and request signing as implemented by this client:

- **Login**: `POST /ISAPI/Bumblebee/Login?CT=0` with plain-password XML. The response contains `SID` and `EncryInfo{Challenge, Iterations, EncryMode}`.
- **Session AES key**: `key = MD5^Iterations(password + challenge)` — iterated MD5 over the hex string, 32 hex chars.
- **Every request**: `POST <path>?SID=<sid>&MT=<logical>`, XML body, plus header `AppendInfo = base64(AES-CBC-PKCS7("<n>:<ne(n)>", key, IV=000102...0f))` where `n` (tokenKeyNum) starts at 11 and increments per request. `ne(n)`: `t=|n·sin n|`, `m=|n·cos n|`; swap if `t<m`; if `m==0` then `m=t`; result is `int(6.28·m + 4·(t−m))`.
- **Door actions** use a raw HTTP `PUT /ISAPI/Bumblebee/ACS/DoorElements/{id}/DoorAction?SID=<sid>` — no `MT` parameter.
- **Error codes**: 0 ok · 2 request body required · 6 invalid method/content · 216 session expired (the client re-logins automatically) · 217 path not supported by this server version.

## Running the example

```bash
export HIK_URL="https://your-hikcentral-host:443"
export HIK_USER="your_username"
export HIK_PASS="your_password"
python examples/list_doors.py
```

## Development

```bash
pip install -e ".[dev]"
pytest        # unit tests, no live server needed
ruff check .  # lint
```

## License

MIT — see [LICENSE](LICENSE).
