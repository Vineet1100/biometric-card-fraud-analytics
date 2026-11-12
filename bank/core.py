"""Authorization decisions and the fraud monitor.

Merchants only ever get a generic response code. The detailed reason goes to the
audit log and the alerts, which only bank-side clients can read.
"""

import hmac
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal

import pyotp

from . import fraud
from .config import Settings
from .security import approval_signature, card_cryptogram, tokenize

APPROVED = "00"  # ISO 8583 style response codes
DECLINED = "05"  # "do not honour" - deliberately vague
PENDING = "P1"  # waiting for the cardholder to approve

MAX_CVV_FAILURES = 3
CVV_LOCKOUT_SECONDS = 60
APPROVAL_TTL_SECONDS = 60
BURST_WINDOW_SECONDS = 300
BURST_THRESHOLD = 3


@dataclass
class Transaction:
    at: float
    channel: str
    card_ref: str
    merchant_id: str
    amount: Decimal
    approved: bool
    reason: str
    security_block: bool
    hour: int


@dataclass
class Approval:
    id: str
    amount: Decimal
    merchant_id: str
    card_ref: str
    expires_at: float


@dataclass
class Bank:
    settings: Settings
    hour_now: Callable[[], int] = lambda: datetime.now().hour  # local hour, a fraud-model feature
    ledger: list[Transaction] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    _alerted: set[str] = field(default_factory=set)
    _approvals: dict[str, Approval] = field(default_factory=dict)
    _used_cvv_steps: set[int] = field(default_factory=set)
    _cvv_failures: int = 0
    _online_blocked_until: float = 0.0
    _last_atc: int = -1
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # --- helpers

    def card_ref(self, pan: str) -> str:
        return tokenize(self.settings.token_key, pan)

    def _record(self, channel, pan, merchant_id, amount, approved, reason, block=False):
        tx = Transaction(
            at=time.time(),
            channel=channel,
            card_ref=self.card_ref(pan),
            merchant_id=merchant_id,
            amount=amount,
            approved=approved,
            reason=reason,
            security_block=block,
            hour=self.hour_now(),
        )
        self.ledger.append(tx)
        self._monitor(len(self.ledger) - 1)
        return tx

    def _totp(self) -> pyotp.TOTP:
        return pyotp.TOTP(
            self.settings.card_otp_secret, digits=3, interval=self.settings.cvv_step_seconds
        )

    # --- in store

    def authorize_in_store(self, pan, amount: Decimal, merchant_id, atc: int, cryptogram: str):
        with self._lock:
            if pan != self.settings.card_pan:
                return DECLINED, self._record(
                    "in_store", pan, merchant_id, amount, False, "unknown card"
                )
            expected = card_cryptogram(
                self.settings.card_key, pan, int(amount * 100), merchant_id, atc
            )
            if not hmac.compare_digest(expected, cryptogram):
                return DECLINED, self._record(
                    "in_store",
                    pan,
                    merchant_id,
                    amount,
                    False,
                    "invalid cryptogram (chip locked or forged)",
                    block=True,
                )
            if atc <= self._last_atc:
                return DECLINED, self._record(
                    "in_store",
                    pan,
                    merchant_id,
                    amount,
                    False,
                    "replayed cryptogram (counter did not increase)",
                    block=True,
                )
            self._last_atc = atc
            return APPROVED, self._record(
                "in_store", pan, merchant_id, amount, True, "chip cryptogram valid"
            )

    # --- online

    def authorize_online(self, pan, cvv, amount: Decimal, merchant_id):
        with self._lock:
            now = time.monotonic()
            if pan != self.settings.card_pan:
                return (
                    DECLINED,
                    None,
                    self._record("online", pan, merchant_id, amount, False, "unknown card"),
                )
            if now < self._online_blocked_until:
                return (
                    DECLINED,
                    None,
                    self._record(
                        "online",
                        pan,
                        merchant_id,
                        amount,
                        False,
                        "online payments paused after repeated wrong CVVs",
                        block=True,
                    ),
                )

            totp = self._totp()
            step = int(time.time() // self.settings.cvv_step_seconds)
            if not hmac.compare_digest(cvv, totp.at(step * self.settings.cvv_step_seconds)):
                self._cvv_failures += 1
                stale = any(
                    hmac.compare_digest(cvv, totp.at((step - k) * self.settings.cvv_step_seconds))
                    for k in range(1, 5)
                )
                reason = "expired CVV (likely leaked card data)" if stale else "incorrect CVV"
                if self._cvv_failures >= MAX_CVV_FAILURES:
                    self._online_blocked_until = now + CVV_LOCKOUT_SECONDS
                    self._cvv_failures = 0
                    reason += "; online payments paused"
                return (
                    DECLINED,
                    None,
                    self._record("online", pan, merchant_id, amount, False, reason, block=True),
                )

            if step in self._used_cvv_steps:
                return (
                    DECLINED,
                    None,
                    self._record(
                        "online",
                        pan,
                        merchant_id,
                        amount,
                        False,
                        "CVV already used (replay)",
                        block=True,
                    ),
                )
            self._used_cvv_steps = {s for s in self._used_cvv_steps if s >= step - 2} | {step}
            self._cvv_failures = 0

            approval = Approval(
                id=secrets.token_urlsafe(16),
                amount=amount,
                merchant_id=merchant_id,
                card_ref=self.card_ref(pan),
                expires_at=now + APPROVAL_TTL_SECONDS,
            )
            self._approvals[approval.id] = approval
            return PENDING, approval, None

    def decide(self, approval_id: str, decision: str, signature: str):
        """The cardholder's device answers the push. Returns None for an unknown id."""
        with self._lock:
            approval = self._approvals.pop(approval_id, None)
            if approval is None:
                return None
            pan = self.settings.card_pan
            if time.monotonic() > approval.expires_at:
                return DECLINED, self._record(
                    "online", pan, approval.merchant_id, approval.amount, False, "approval expired"
                )
            expected = approval_signature(self.settings.device_key, approval_id, decision)
            if not hmac.compare_digest(expected, signature):
                return DECLINED, self._record(
                    "online",
                    pan,
                    approval.merchant_id,
                    approval.amount,
                    False,
                    "approval not signed by the cardholder's device",
                    block=True,
                )
            if decision == "deny":
                return DECLINED, self._record(
                    "online",
                    pan,
                    approval.merchant_id,
                    approval.amount,
                    False,
                    "cardholder denied the purchase",
                    block=True,
                )
            return APPROVED, self._record(
                "online", pan, approval.merchant_id, approval.amount, True, "approved by cardholder"
            )

    # --- fraud monitor

    def _alert(self, key: str, severity: str, title: str, tx: Transaction) -> None:
        if key in self._alerted:
            return
        self._alerted.add(key)
        self.alerts.append(
            {
                "at": datetime.fromtimestamp(tx.at, timezone.utc).isoformat(timespec="seconds"),
                "severity": severity,
                "title": title,
                "channel": tx.channel,
                "merchant_id": tx.merchant_id,
                "amount": str(tx.amount),
                "card_ref": tx.card_ref,
            }
        )

    def _monitor(self, i: int) -> None:
        tx = self.ledger[i]
        if tx.security_block:
            recent = [
                t
                for t in self.ledger
                if t.security_block
                and t.channel == tx.channel
                and tx.at - t.at <= BURST_WINDOW_SECONDS
            ]
            if len(recent) == BURST_THRESHOLD:
                self._alert(
                    f"burst-{i}",
                    "high",
                    f"{BURST_THRESHOLD} blocked {tx.channel} attempts in 5 minutes",
                    tx,
                )
        if "expired CVV" in tx.reason:
            self._alert(f"leak-{i}", "high", "stolen card data used online", tx)
        if "denied" in tx.reason:
            self._alert(f"deny-{i}", "high", "purchase denied by cardholder", tx)
        if tx.approved:
            result = fraud.score(float(tx.amount), tx.hour, tx.channel == "online")
            if result.flagged:
                self._alert(f"score-{i}", "medium", f"unusual purchase: {result.reason}", tx)

    def pending(self) -> list[Approval]:
        with self._lock:
            now = time.monotonic()
            return [a for a in self._approvals.values() if a.expires_at > now]

    def stats(self) -> dict:
        with self._lock:
            approved = [t for t in self.ledger if t.approved]
            return {
                "attempts": len(self.ledger),
                "approved": len(approved),
                "blocked": sum(t.security_block for t in self.ledger),
                "alerts": len(self.alerts),
                "approved_volume": str(sum((t.amount for t in approved), Decimal("0"))),
            }
