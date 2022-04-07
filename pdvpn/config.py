#!/usr/bin/env python3

"""
Config for PD VPN.
"""

# ------------------------------ Standard constants ------------------------------ #

MASTER_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEA1ztvdU1UE0QJrqqh/LP1
88RIGmLdLjLdHI+bZ/c42ZU40RTr+wTZplnuJqbYnoZrzOXwuhTomf9SdgtJQ4HE
LP4rPYMQwLO6GHzWAT1Z32qZnQdfZpoZQfWMUK3pZT601GGY5V+5lf1++bD6ve42
tFUGgjn0Ptu6KtJ+cCYzghi/aK02FLxzKQaXvtI4MaWM7Al7qWYyUUu32KVwRv8M
009tYMSEfAIlWH5D6RtvxvOd+vkN6PPYsktFBUeq1suJYWx+3tS2SNmzWESH/3SR
JOYm+2/0w8bgTe92mkZazaLRo4NwozV/zSis3+KtVLexqSgFNG3RGT/8jysfPBAD
qHyMzRWztQUFsJ0VFSYwo0cxmZTlX5Uy9rQIsse8IBSXNfZ8asUSXdn8ODsI4Xhu
Yy5XWFxMg+B1DKImOEMltB2TwSw7oSJwy4glP/pZAzmmpKbXU4YutvN3lCCMGzhm
9GbCinaAbHherehbWwQ5uvTMyeBIO/XYSwFTcx/p2kEtY/TUj9U66zPCc4Qln63U
DvPBspDfDKiHurofwcYU5r3w6S+UWGMcUDJfy8Cosvuk9ZXyUJ3gE28N9Mak8EZ/
VhxKNVhKDITDwRjzXoCjYAa05v56Pv/eKlxreqWSV1KhMbdUQibi64Br1i2MV9bT
pyVRphNiz19xKE5VjwXNF6mOaabK7B5TWR097W94WgmGaRfy1sifRhVFYb3D/g/J
7COzFKG9B4xlx45lOMEKqLTZCuNoi1EqQDLKVx4iq1IxVQsf+RxL6UTWaa5LBGz6
WIYp06Rd0PR6kC9+JIGYK/VFcECh6KdIP8ZfumHLvH0fOLVZj4Rho6cPmT1Z9W9Y
WHLEtC1GWTfCIRaqERMeTvTcNyoRPiXiysMBlaA25sZU+sMhFq0e2olPAh+cyqzk
h/wLukRFz/+WI3IxcjmomfJi7rZ4NHEVp+g7kCJZDzezBfqei0nIPut0W7Xh06v8
p5f7XzOV+JNQzbBVQRSc10AByTdODqAfjpeEKX2sVBhUEnGiWDQjQc5NkBthlh8x
cLzkro5b/OowiMeEmDI144NMbUoSTfGUgeoTqdxthOvy1Lu6fNRmOg7ZINijPXWg
HlRUjLrCWRueqwf4OvOH3jMKHtM0AdwJvJh9YPWDaM6LyeFo67Vz7r7ZbHivUa70
9zR/EHmXhgTdoMCmAbsqf7V2fqp27D4wp2AkclSJ99LsUtFWjKgYR3PA1fJ4WGWx
Zp9Z4AAMUpu7LP3etfgYRvW4cZltVLspBQR2sVSAALe7x10/q6divfhFwTUciggl
e+IVrwO0B0R7DCH/vbeb4fIPxYHu7wndP55HUEFnCJ3O8jFwqY6eWdQyi+wrY8MJ
2wIDAQAB
-----END PUBLIC KEY-----"""

CLIENT = "py3"  # Client name/type
VERSION = "0.1.3"  # Client version

NODE_LIST_TRUST_THRESHOLD = 0.9  # % of valid nodes required to trust an unverified node

RSA_KEY_SIZE = 2048
DHKE_KEY_SIZE = 512
TUNNEL_RSA_KEY_SIZE = 1024

KEEP_ALIVE_INTERVAL = 60  # Seconds
TUNNEL_KEEP_ALIVE_INTERVAL = 30  # Seconds
TUNNEL_EXPIRY = 60  # Seconds

# ------------------------------ Data provider stuff ------------------------------ #

DATA_FILE = "vpnconf"

# ------------------------------ Tunnel stuff ------------------------------ #

TUNNEL_TIMEOUT = 30  # Seconds
# TODO: Uh idk prolly proper data to sign, like the time?
TUNNEL_DATA_RANDOM_SIZE = 16  # The distinction is so that one can't be copied
TUNNEL_CLOSE_RANDOM_SIZE = 32

# ------------------------------ Connection stuff ------------------------------ #

INITIAL_NODE = True  # Are we the initial node on the network?

INBOUND_ENABLED = True
INBOUND_HOSTNAME = "localhost"  # Local node server's hostname
INBOUND_PORT = 5002  # Local node server's port, should prolly be 5002
