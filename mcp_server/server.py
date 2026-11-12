"""MCP server for AI agents:  python -m mcp_server.server

Security choices:
- read-only: no tool can authorize, approve or refund a payment
- no secrets in output: the bank never returns card numbers, CVVs or keys
- least privilege: it signs in as the "fraud-agent" client, whose scopes are
  only fraud:score, alerts:read and stats:read, so even a compromised server
  can't call the payment endpoints
- stdio transport only: it runs as a local process for the agent and opens no
  network port
- tool output is built from fixed templates and validated ids, so a merchant
  can't plant instructions for the agent in an alert (prompt injection)
"""

import logging
import os
import sys
from decimal import Decimal
from typing import Annotated, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from bank.client import BankClient, BankError

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)

INSTRUCTIONS = (
    "Read-only fraud tools for the biometric card bank. Use them to check whether a "
    "purchase looks like the cardholder, review fraud alerts and see payment totals. "
    "They cannot move money or reveal card numbers, CVVs or keys."
)


def create_server(bank: BankClient) -> MCPServer:
    server = MCPServer("biometric-card-fraud", instructions=INSTRUCTIONS)

    def call(method: str, path: str, payload: dict | None = None, params: dict | None = None):
        try:
            return bank.request(method, path, payload, params)
        except BankError:
            raise RuntimeError("the bank service is unavailable or refused the request") from None

    @server.tool(annotations=READ_ONLY)
    def score_transaction(
        amount: Annotated[
            Decimal, Field(gt=0, le=10_000, decimal_places=2, description="Amount in CAD")
        ],
        hour: Annotated[int, Field(ge=0, le=23, description="Local hour of the purchase, 0-23")],
        channel: Literal["in_store", "online"],
    ) -> dict:
        """Check whether a purchase fits the cardholder's normal spending.

        Returns whether it's flagged, why, the robust z-score of the amount and
        whether the pattern model flagged it.
        """
        return call(
            "POST", "/v1/fraud/score", {"amount": str(amount), "hour": hour, "channel": channel}
        )

    @server.tool(annotations=READ_ONLY)
    def list_fraud_alerts(
        limit: Annotated[int, Field(ge=1, le=50, description="How many recent alerts")] = 10,
    ) -> dict:
        """List the most recent fraud alerts, newest first. Card numbers appear only as tokens."""
        return call("GET", "/v1/alerts", params={"limit": limit})

    @server.tool(annotations=READ_ONLY)
    def get_payment_stats() -> dict:
        """Totals for all payment attempts: approved, blocked, alerts and approved volume."""
        return call("GET", "/v1/stats")

    return server


def main() -> None:
    logging.getLogger("httpx").setLevel(logging.WARNING)  # don't log every request URL
    url = os.environ.get("MCP_BANK_URL", "http://127.0.0.1:8080")
    client_id = os.environ.get("MCP_CLIENT_ID", "")
    secret = os.environ.get("MCP_CLIENT_SECRET", "")
    if not client_id or len(secret) < 32:
        sys.exit("set MCP_CLIENT_ID and MCP_CLIENT_SECRET (see python -m bank.keys)")
    try:
        bank = BankClient(url, client_id, secret)
    except BankError as exc:
        sys.exit(str(exc))
    create_server(bank).run("stdio")


if __name__ == "__main__":
    main()
