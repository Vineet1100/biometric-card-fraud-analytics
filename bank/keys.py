"""Print a fresh .env file with random keys:  python -m bank.keys > .env

Each client gets only the scopes it needs. Keep the output out of git
(.env is already in .gitignore) and rotate the keys if they ever leak.
"""

import json
import secrets

import pyotp


def generate() -> str:
    def key() -> str:
        return secrets.token_urlsafe(48)

    clients = {
        "merchant-pos": {"secret": key(), "scopes": ["authorize:in_store"]},
        "merchant-web": {"secret": key(), "scopes": ["authorize:online"]},
        "cardholder-app": {"secret": key(), "scopes": ["approvals:decide"]},
        "fraud-agent": {"secret": key(), "scopes": ["fraud:score", "alerts:read", "stats:read"]},
    }
    lines = [
        "BANK_ENV=production",
        f"BANK_CARD_OTP_SECRET={pyotp.random_base32(length=32)}",
        f"BANK_CARD_KEY={key()}",
        f"BANK_DEVICE_KEY={key()}",
        f"BANK_TOKEN_KEY={key()}",
        f"BANK_CLIENTS='{json.dumps(clients)}'",
        "",
        "# the MCP server uses the fraud-agent credentials",
        "MCP_BANK_URL=http://127.0.0.1:8080",
        "MCP_CLIENT_ID=fraud-agent",
        f"MCP_CLIENT_SECRET={clients['fraud-agent']['secret']}",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(generate())
