import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from bank.client import BankClient, BankError
from mcp_server.server import create_server


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def server(clients):
    return create_server(clients["fraud-agent"])


def test_every_tool_is_read_only(server):
    tools = run(server.list_tools())
    assert {t.name for t in tools} == {
        "score_transaction",
        "list_fraud_alerts",
        "get_payment_stats",
    }
    assert all(t.annotations.read_only_hint and not t.annotations.destructive_hint for t in tools)


def test_score_tool(server):
    result = run(
        server.call_tool("score_transaction", {"amount": "1200", "hour": 14, "channel": "online"})
    )
    assert json.loads(result.content[0].text)["flagged"] is True


def test_tools_reject_bad_input(server):
    with pytest.raises(ToolError):
        run(server.call_tool("score_transaction", {"amount": "-5", "hour": 99, "channel": "atm"}))
    with pytest.raises(ToolError):
        run(server.call_tool("list_fraud_alerts", {"limit": 10_000}))


def test_server_with_payment_credentials_gets_nothing(clients):
    # if someone swaps in merchant credentials, the bank still refuses the fraud endpoints
    server = create_server(clients["merchant-web"])
    with pytest.raises(ToolError):
        run(server.call_tool("list_fraud_alerts", {"limit": 5}))


def test_output_never_contains_card_numbers(server, clients, settings, cvv):
    clients["merchant-web"].request(
        "POST",
        "/v1/authorize/online",
        {
            "pan": settings.card_pan,
            "cvv": "000" if cvv != "000" else "111",
            "amount": "5.00",
            "merchant_id": "northwind",
        },
    )
    text = run(server.call_tool("list_fraud_alerts", {"limit": 10})).content[0].text
    text += run(server.call_tool("get_payment_stats", {})).content[0].text
    assert settings.card_pan not in text


def test_credentials_never_sent_over_plain_http():
    with pytest.raises(BankError):
        BankClient("http://bank.example.com", "fraud-agent", "s" * 40)
    BankClient("https://bank.example.com", "fraud-agent", "s" * 40)  # fine over TLS
