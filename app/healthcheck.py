"""Docker HEALTHCHECK: hit /healthz on the local HTTPS listener."""
import ssl
import sys
import urllib.request

ctx = ssl._create_unverified_context()  # loopback check only; the cert is issued for the public hostname
try:
    sys.exit(0 if urllib.request.urlopen("https://127.0.0.1:8000/healthz", timeout=4, context=ctx).status == 200 else 1)
except Exception:
    sys.exit(1)
