"""Run the bank API:  python -m bank

Binds to 127.0.0.1 by default. Exposing it on a network needs a TLS certificate,
either here (BANK_TLS_CERT / BANK_TLS_KEY) or from a reverse proxy in front of it.
"""

import os
import sys

import uvicorn

from .api import create_app
from .config import ConfigError, load_settings


def main() -> None:
    try:
        settings = load_settings()
    except ConfigError as exc:
        sys.exit(f"config error: {exc}\nGenerate keys with: python -m bank.keys > .env")

    host = os.environ.get("BANK_HOST", "127.0.0.1")
    cert, key = os.environ.get("BANK_TLS_CERT"), os.environ.get("BANK_TLS_KEY")
    behind_proxy = os.environ.get("BANK_BEHIND_TLS_PROXY") == "1"
    if host not in ("127.0.0.1", "localhost", "::1") and not (cert and key) and not behind_proxy:
        sys.exit("refusing to listen on a network address without TLS")

    uvicorn.run(
        create_app(settings),
        host=host,
        port=int(os.environ.get("BANK_PORT", "8080")),
        ssl_certfile=cert,
        ssl_keyfile=key,
        server_header=False,
        date_header=False,
        proxy_headers=behind_proxy,
    )


if __name__ == "__main__":
    main()
