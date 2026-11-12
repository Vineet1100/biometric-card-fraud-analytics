import json
import secrets
import time

import pyotp
import pytest
from fastapi.testclient import TestClient

from bank.api import create_app
from bank.client import BankClient
from bank.config import Client, Settings
from bank.security import sign_request

SCOPES = {
    "merchant-pos": {"authorize:in_store"},
    "merchant-web": {"authorize:online"},
    "cardholder-app": {"approvals:decide"},
    "fraud-agent": {"fraud:score", "alerts:read", "stats:read"},
}


def make_settings(tmp_path, **overrides) -> Settings:
    clients = {
        cid: Client(cid, secrets.token_urlsafe(48).encode(), frozenset(scopes))
        for cid, scopes in SCOPES.items()
    }
    values = dict(
        env="production",
        card_pan="4111111111111111",
        card_otp_secret=pyotp.random_base32(length=32),
        card_key=secrets.token_bytes(32),
        device_key=secrets.token_bytes(32),
        token_key=secrets.token_bytes(32),
        clients=clients,
        audit_log_path=str(tmp_path / "audit.log"),
    )
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def app(settings):
    app = create_app(settings)
    # a normal shopping hour, so tests don't depend on the clock
    app.state.bank.hour_now = lambda: 13
    return app


@pytest.fixture
def http(app):
    return TestClient(app)


@pytest.fixture
def clients(settings, http):
    return {
        cid: BankClient("http://testserver", cid, c.secret.decode(), http)
        for cid, c in settings.clients.items()
    }


@pytest.fixture
def cvv(settings):
    return pyotp.TOTP(settings.card_otp_secret, digits=3, interval=settings.cvv_step_seconds).now()


def signed(http, settings, client_id, method, path, payload=None, **tweaks):
    """Send a signed request by hand, with optional tampering for attack tests."""
    body = b"" if payload is None else json.dumps(payload).encode()
    timestamp = str(tweaks.get("timestamp", int(time.time())))
    nonce = tweaks.get("nonce", secrets.token_hex(16))
    secret = settings.clients[client_id].secret
    signature = tweaks.get("signature") or sign_request(
        secret, method, path, timestamp, nonce, body
    )
    headers = {
        "Content-Type": "application/json",
        "X-Client-Id": client_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }
    return http.request(method, path, content=tweaks.get("body", body), headers=headers)
