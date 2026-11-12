"""Small client that signs requests to the bank API (used by the MCP server and tests)."""

import json
import secrets
import time
from urllib.parse import urlparse

import httpx

from .security import sign_request

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}


class BankError(RuntimeError):
    pass


class BankClient:
    def __init__(
        self, base_url: str, client_id: str, secret: str, http: httpx.Client | None = None
    ):
        url = urlparse(base_url)
        # credentials only travel over TLS, unless the bank is on this machine
        if url.scheme != "https" and url.hostname not in LOCAL_HOSTS:
            raise BankError("refusing to send credentials over plain HTTP to a remote host")
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self._secret = secret.encode()
        self._http = http or httpx.Client(timeout=10.0, follow_redirects=False)

    def request(
        self, method: str, path: str, payload: dict | None = None, params: dict | None = None
    ):
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        headers = {
            "Content-Type": "application/json",
            "X-Client-Id": self.client_id,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": sign_request(self._secret, method, path, timestamp, nonce, body),
        }
        response = self._http.request(
            method, self.base_url + path, content=body, headers=headers, params=params
        )
        if response.status_code >= 400:
            raise BankError(f"bank returned {response.status_code}")
        return response.json()
