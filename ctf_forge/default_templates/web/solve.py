#!/usr/bin/env python3
# %challname% (web solve script)

import requests

URL = "%connection_info%"  # or hardcoded target

session = requests.Session()
resp = session.get(URL, timeout=10)
print(resp.status_code)
print(resp.text[:500])
