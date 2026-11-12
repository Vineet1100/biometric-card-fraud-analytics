"""Payment flows: in-store cryptograms, online CVV + approval, and fraud alerts."""

import time

import pyotp
import pytest

from bank.client import BankError
from bank.security import approval_signature, card_cryptogram

PAN = "4111111111111111"


def tap(clients, settings, amount="42.50", atc=1, key=None, signed_amount=None):
    cents = int(float(signed_amount or amount) * 100)
    cryptogram = card_cryptogram(key or settings.card_key, PAN, cents, "corner-market", atc)
    payload = {
        "pan": PAN,
        "amount": amount,
        "merchant_id": "corner-market",
        "atc": atc,
        "cryptogram": cryptogram,
    }
    return clients["merchant-pos"].request("POST", "/v1/authorize/in-store", payload)[
        "response_code"
    ]


def pay_online(clients, cvv, amount="249.99"):
    payload = {"pan": PAN, "cvv": cvv, "amount": amount, "merchant_id": "northwind"}
    return clients["merchant-web"].request("POST", "/v1/authorize/online", payload)


def answer(clients, settings, approval_id, decision, key=None):
    sig = approval_signature(key or settings.device_key, approval_id, decision)
    return clients["cardholder-app"].request(
        "POST", f"/v1/approvals/{approval_id}", {"decision": decision, "signature": sig}
    )["response_code"]


def alert_titles(clients):
    return [a["title"] for a in clients["fraud-agent"].request("GET", "/v1/alerts")["alerts"]]


# in store


def test_unlocked_card_is_approved(clients, settings):
    assert tap(clients, settings) == "00"


def test_locked_or_cloned_card_is_declined(clients, settings):
    # without the card's key (no fingerprint, or a cloned card) the cryptogram is wrong
    assert tap(clients, settings, key=b"x" * 32) == "05"


def test_replayed_cryptogram_is_declined(clients, settings):
    assert tap(clients, settings, atc=5) == "00"
    assert tap(clients, settings, atc=5) == "05"
    assert tap(clients, settings, atc=4) == "05"


def test_terminal_cannot_change_the_amount(clients, settings):
    assert tap(clients, settings, amount="900.00", signed_amount="42.50") == "05"


def test_card_testing_raises_an_alert(clients, settings):
    for atc in range(3):
        tap(clients, settings, atc=atc, key=b"x" * 32)
    assert "3 blocked in_store attempts in 5 minutes" in alert_titles(clients)


# online


def test_valid_cvv_needs_cardholder_approval(clients, settings, cvv):
    r = pay_online(clients, cvv)
    assert r["response_code"] == "P1"
    pending = clients["cardholder-app"].request("GET", "/v1/approvals")["approvals"]
    assert pending[0]["approval_id"] == r["approval_id"]
    assert answer(clients, settings, r["approval_id"], "approve") == "00"


def test_denied_purchase_is_declined_and_flagged(clients, settings, cvv):
    r = pay_online(clients, cvv)
    assert answer(clients, settings, r["approval_id"], "deny") == "05"
    assert "purchase denied by cardholder" in alert_titles(clients)


def test_approval_from_another_device_is_declined(clients, settings, cvv):
    r = pay_online(clients, cvv)
    assert answer(clients, settings, r["approval_id"], "approve", key=b"y" * 32) == "05"


def test_approval_works_only_once(clients, settings, cvv):
    r = pay_online(clients, cvv)
    assert answer(clients, settings, r["approval_id"], "approve") == "00"
    with pytest.raises(BankError, match="404"):
        answer(clients, settings, r["approval_id"], "approve")


def test_cvv_works_only_once(clients, cvv):
    assert pay_online(clients, cvv)["response_code"] == "P1"
    assert pay_online(clients, cvv)["response_code"] == "05"


def test_stolen_cvv_is_declined_and_flagged(clients, settings):
    totp = pyotp.TOTP(settings.card_otp_secret, digits=3, interval=settings.cvv_step_seconds)
    old = totp.at(time.time() - 2 * settings.cvv_step_seconds)
    if old == totp.now():  # 1 in 1000 chance the old code equals the new one
        return
    assert pay_online(clients, old)["response_code"] == "05"
    assert "stolen card data used online" in alert_titles(clients)


def test_guessing_cvvs_pauses_online_payments(clients, settings, cvv):
    wrong = [c for c in ("000", "111", "222", "333") if c != cvv][:3]
    for guess in wrong:
        assert pay_online(clients, guess)["response_code"] == "05"
    # even the right code is refused while payments are paused
    assert pay_online(clients, cvv)["response_code"] == "05"


# fraud scoring


def score(clients, amount, hour, channel):
    payload = {"amount": amount, "hour": hour, "channel": channel}
    return clients["fraud-agent"].request("POST", "/v1/fraud/score", payload)


def test_normal_purchases_pass(clients):
    assert not score(clients, "42.50", 12, "in_store")["flagged"]
    assert not score(clients, "85.00", 20, "online")["flagged"]


def test_unusual_purchases_are_flagged(clients):
    assert score(clients, "1200.00", 14, "online")["flagged"]
    night = score(clients, "42.50", 3, "in_store")
    assert night["flagged"] and night["pattern_flagged"]


def test_stats(clients, settings, cvv):
    tap(clients, settings)
    stats = clients["fraud-agent"].request("GET", "/v1/stats")
    assert stats["attempts"] == 1 and stats["approved"] == 1 and stats["approved_volume"] == "42.50"
