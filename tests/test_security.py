"""Each test is an attack the API has to stop."""

import json
import os
import secrets
import time

import pytest
from fastapi.testclient import TestClient

from bank.api import create_app
from bank.config import ConfigError, load_settings
from tests.conftest import make_settings, signed

ONLINE = "/v1/authorize/online"


def online_payload(cvv="123"):
    return {"pan": "4111111111111111", "cvv": cvv, "amount": "10.00", "merchant_id": "northwind"}


def test_unsigned_request_is_rejected(http):
    assert http.post(ONLINE, json=online_payload()).status_code == 401


def test_unknown_client_is_rejected(http, settings):
    r = http.post(ONLINE, json=online_payload(), headers={"X-Client-Id": "intruder"})
    assert r.status_code == 401


def test_forged_signature_is_rejected(http, settings):
    r = signed(http, settings, "merchant-web", "POST", ONLINE, online_payload(), signature="0" * 64)
    assert r.status_code == 401


def test_tampered_body_is_rejected(http, settings):
    # signed for $10, sent with $9000
    tampered = online_payload() | {"amount": "9000.00"}
    r = signed(
        http,
        settings,
        "merchant-web",
        "POST",
        ONLINE,
        online_payload(),
        body=json.dumps(tampered).encode(),
    )
    assert r.status_code == 401


def test_old_request_is_rejected(http, settings):
    r = signed(
        http,
        settings,
        "merchant-web",
        "POST",
        ONLINE,
        online_payload(),
        timestamp=int(time.time()) - 3600,
    )
    assert r.status_code == 401


def test_replayed_request_is_rejected(http, settings):
    nonce = secrets.token_hex(16)
    first = signed(http, settings, "merchant-web", "POST", ONLINE, online_payload(), nonce=nonce)
    second = signed(http, settings, "merchant-web", "POST", ONLINE, online_payload(), nonce=nonce)
    assert first.status_code == 200
    assert second.status_code == 401


def test_client_cannot_use_another_clients_scope(http, settings):
    # the fraud tools' credentials can't authorize payments
    r = signed(http, settings, "fraud-agent", "POST", ONLINE, online_payload())
    assert r.status_code == 403


def test_unexpected_fields_are_rejected(http, settings):
    payload = online_payload() | {"is_admin": True}
    assert signed(http, settings, "merchant-web", "POST", ONLINE, payload).status_code == 422


@pytest.mark.parametrize(
    "field,value",
    [
        ("amount", "-1"),
        ("amount", "1000000"),
        ("amount", "1.001"),
        ("cvv", "12a"),
        ("pan", "4111"),
        ("merchant_id", "<script>"),
    ],
)
def test_bad_values_are_rejected(http, settings, field, value):
    payload = online_payload() | {field: value}
    assert signed(http, settings, "merchant-web", "POST", ONLINE, payload).status_code == 422


def test_oversized_body_is_rejected(http, settings):
    r = signed(http, settings, "merchant-web", "POST", ONLINE, {"x": "a" * 20_000})
    assert r.status_code == 413


def test_rate_limit(tmp_path):
    settings = make_settings(tmp_path, requests_per_minute=3)
    http = TestClient(create_app(settings))
    codes = [
        signed(http, settings, "fraud-agent", "GET", "/v1/stats").status_code for _ in range(5)
    ]
    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429]


def test_repeated_bad_signatures_lock_out_the_source(http, settings):
    for _ in range(20):
        signed(http, settings, "merchant-web", "POST", ONLINE, online_payload(), signature="0" * 64)
    # even a correct request from the same address is now refused for a while
    assert (
        signed(http, settings, "merchant-web", "POST", ONLINE, online_payload()).status_code == 429
    )


def test_errors_and_headers_reveal_nothing(http):
    r = http.get("/healthz")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    assert "server" not in r.headers
    assert http.post(ONLINE, json={}).json() == {"detail": "unauthorized"}


def test_api_docs_hidden_in_production(http, tmp_path):
    assert http.get("/docs").status_code == 404
    assert http.get("/openapi.json").status_code == 404
    dev = TestClient(create_app(make_settings(tmp_path, env="dev")))
    assert dev.get("/docs").status_code == 200


def test_audit_log_has_no_card_data(http, settings, clients, cvv):
    r = clients["merchant-web"].request("POST", ONLINE, online_payload(cvv))
    clients["cardholder-app"].request("GET", "/v1/approvals")
    with open(settings.audit_log_path) as f:
        log = f.read()
    assert r["response_code"] == "P1"
    assert settings.card_pan not in log
    assert f'"{cvv}"' not in log
    assert "tok_" in log
    assert oct(os.stat(settings.audit_log_path).st_mode & 0o777) == "0o600"


def test_missing_or_weak_keys_stop_startup(monkeypatch):
    for name in (
        "BANK_CARD_KEY",
        "BANK_DEVICE_KEY",
        "BANK_TOKEN_KEY",
        "BANK_CARD_OTP_SECRET",
        "BANK_CLIENTS",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ConfigError):
        load_settings()
    monkeypatch.setenv("BANK_CARD_OTP_SECRET", "A" * 32)
    monkeypatch.setenv("BANK_CARD_KEY", "short")
    with pytest.raises(ConfigError):
        load_settings()


def test_unknown_scope_stops_startup(monkeypatch):
    for name in ("BANK_CARD_KEY", "BANK_DEVICE_KEY", "BANK_TOKEN_KEY"):
        monkeypatch.setenv(name, "k" * 40)
    monkeypatch.setenv("BANK_CARD_OTP_SECRET", "A" * 32)
    monkeypatch.setenv(
        "BANK_CLIENTS", '{"x": {"secret": "' + "s" * 40 + '", "scopes": ["admin:all"]}}'
    )
    with pytest.raises(ConfigError):
        load_settings()


def test_settings_never_print_keys(settings):
    text = repr(settings)
    assert settings.card_key.hex() not in text
    for client in settings.clients.values():
        assert client.secret.decode() not in text
