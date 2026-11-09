"""Docker HEALTHCHECK: hit /healthz on the local listener (HTTPS unless HTTP_TLS=false)."""
import os
import ssl
import sys
import urllib.request

tls = os.environ.get("HTTP_TLS", "true").strip().lower() in ("1", "true", "yes", "on")
url = f"{'https' if tls else 'http'}://127.0.0.1:8000/healthz"
ctx = ssl._create_unverified_context()  # loopback check only; the cert is issued for the public hostname
try:
    sys.exit(0 if urllib.request.urlopen(url, timeout=4, context=ctx).status == 200 else 1)
except Exception:
    sys.exit(1)
