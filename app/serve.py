"""Container entrypoint: run the relay over HTTPS only (there is no plain-HTTP listener)."""
from __future__ import annotations

import logging
import sys

import uvicorn

from .checkconfig import main as check_config
from .config import Settings
from .tls import resolve_tls_files


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if check_config() != 0:  # clear list of problems instead of a traceback
        sys.exit(1)
    settings = Settings.from_env()
    cert, key = resolve_tls_files(settings)
    tls = {"ssl_certfile": cert, "ssl_keyfile": key}
    logging.getLogger("relay").info("Serving HTTPS with %s", cert)
    # One worker only: the delivery queue and SMTP server live in the app process.
    # Proxy headers are handled by the app itself (TRUST_PROXY / TRUSTED_PROXIES).
    uvicorn.run("app.main:_default_app", factory=True, host="0.0.0.0", port=8000, workers=1,
                proxy_headers=False, server_header=False, log_config=None, **tls)


if __name__ == "__main__":
    main()
