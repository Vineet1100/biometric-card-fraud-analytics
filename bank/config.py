"""Settings for the bank service.

Everything secret comes from environment variables. The service refuses to start
if a key is missing or too short, instead of falling back to a default.
Generate a fresh set with:  python -m bank.keys > .env
"""

import json
import os
from dataclasses import dataclass, field

MIN_KEY_BYTES = 32

SCOPES = {
    "authorize:in_store",  # card terminals
    "authorize:online",  # online checkouts
    "approvals:decide",  # the cardholder's own device
    "fraud:score",  # fraud tools (e.g. the MCP server)
    "alerts:read",
    "stats:read",
}


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Client:
    id: str
    secret: bytes
    scopes: frozenset[str]


@dataclass(frozen=True)
class Settings:
    env: str
    card_pan: str
    card_otp_secret: str  # base32 TOTP secret shared with the card
    card_key: bytes  # signs in-store cryptograms on the card
    device_key: bytes  # signs purchase approvals on the cardholder's device
    token_key: bytes  # tokenizes card numbers in logs
    clients: dict[str, Client] = field(repr=False)
    cvv_step_seconds: int = 120
    max_clock_skew_seconds: int = 300
    requests_per_minute: int = 60
    max_body_bytes: int = 16_384
    audit_log_path: str = "audit.log"

    def __repr__(self) -> str:  # never print keys by accident
        return f"Settings(env={self.env!r}, clients={sorted(self.clients)})"


def _secret(name: str) -> bytes:
    value = os.environ.get(name, "")
    if len(value.encode()) < MIN_KEY_BYTES:
        raise ConfigError(f"{name} must be set to at least {MIN_KEY_BYTES} bytes")
    return value.encode()


def _clients(raw: str) -> dict[str, Client]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError("BANK_CLIENTS is not valid JSON") from exc
    clients = {}
    for client_id, entry in data.items():
        secret = str(entry.get("secret", "")).encode()
        scopes = frozenset(entry.get("scopes", []))
        if len(secret) < MIN_KEY_BYTES:
            raise ConfigError(f"client {client_id!r} needs a secret of {MIN_KEY_BYTES}+ bytes")
        unknown = scopes - SCOPES
        if unknown:
            raise ConfigError(f"client {client_id!r} has unknown scopes {sorted(unknown)}")
        clients[client_id] = Client(client_id, secret, scopes)
    if not clients:
        raise ConfigError("BANK_CLIENTS has no clients")
    return clients


def load_settings() -> Settings:
    otp_secret = os.environ.get("BANK_CARD_OTP_SECRET", "")
    if len(otp_secret) < 32:
        raise ConfigError("BANK_CARD_OTP_SECRET must be a base32 secret of 32+ characters")
    return Settings(
        env=os.environ.get("BANK_ENV", "production"),
        card_pan=os.environ.get("BANK_CARD_PAN", "4111111111111111"),
        card_otp_secret=otp_secret,
        card_key=_secret("BANK_CARD_KEY"),
        device_key=_secret("BANK_DEVICE_KEY"),
        token_key=_secret("BANK_TOKEN_KEY"),
        clients=_clients(os.environ.get("BANK_CLIENTS", "")),
        audit_log_path=os.environ.get("BANK_AUDIT_LOG", "audit.log"),
    )
