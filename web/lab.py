"""The card lab's card, merchants and bank for one visitor, in Python.

Each browser gets its own ``CardLab``: its own TOTP secret, unlock window, failure
counters, pending approval, payment log and fraud alerts. The rules are the same as the
Streamlit app (``app.py``) and the bank API (``bank/``):

- the chip only pays for 15 s after the owner's fingerprint matches; 3 wrong fingers
  lock the sensor for 30 s
- online, the CVV is a 3-digit TOTP code that changes every 2 minutes; each code works
  once, an expired code is recognised as leaked data, and 3 wrong codes pause online
  payments for 60 s
- a valid CVV still needs the owner to approve the purchase within 60 s
- after every attempt the fraud monitor looks across the whole log for card testing,
  leaked data, denied purchases and spending that doesn't fit the owner
"""
from __future__ import annotations

import random
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import pyotp

from bank import fraud

UNLOCK_SECONDS = 15
BIO_MAX_FAILURES, BIO_LOCK_SECONDS = 3, 30
CVV_STEP_SECONDS, CVV_DIGITS = 120, 3
CVV_MAX_FAILURES, CVV_LOCK_SECONDS = 3, 60
STALE_LOOKBACK_STEPS = 4
PUSH_SECONDS = 60
BURST_SECONDS, BURST_COUNT = 5 * 60, 3

CARD_PAN = "4111111111111111"
MERCHANT_STORE = "Corner Market"
MERCHANT_ONLINE = "Northwind Electronics"
MISSIONS = (1, 2, 3, 4)


@dataclass
class Entry:
    t: float                  # unix time
    channel: str              # "In-Store" or "Online"
    amount: float
    ok: bool
    reason: str
    block: bool               # counted as a blocked fraud attempt
    hour: int                 # the visitor's local hour, for the fraud model

    def public(self) -> dict:
        d = asdict(self)
        d["time"] = datetime.fromtimestamp(self.t, timezone.utc).isoformat()
        return d


@dataclass
class Alert:
    key: str
    sev: str                  # "high" or "med"
    title: str
    text: str
    t: float = field(default_factory=time.time)


@dataclass
class Pending:
    amount: float
    hour: int
    expires: float


class CardLab:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.totp = pyotp.TOTP(pyotp.random_base32(), digits=CVV_DIGITS, interval=CVV_STEP_SECONDS)
        self.unlocked_until = 0.0
        self.bio_fails = 0
        self.bio_locked_until = 0.0
        self.cvv_fails = 0
        self.online_blocked_until = 0.0
        self.used_steps: set[int] = set()
        self.pending: Pending | None = None
        self.ledger: list[Entry] = []
        self.alerts: list[Alert] = []
        self._alert_keys: set[str] = set()
        self.done: set[int] = set()
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ card
    def step(self, at: float | None = None) -> int:
        return int((self.clock() if at is None else at) // CVV_STEP_SECONDS)

    def code_at(self, step: int) -> str:
        return self.totp.at(step * CVV_STEP_SECONDS)

    def cvv_now(self) -> str:
        return self.code_at(self.step())

    def scan(self, owner: bool) -> dict:
        """A fingerprint scan on the card's sensor. Only yes or no ever reaches the bank."""
        now = self.clock()
        if now < self.bio_locked_until:
            left = int(self.bio_locked_until - now + 0.999)
            return dict(result="locked", message=f"Sensor is locked after 3 failed scans. Try again in {left} seconds.")
        if owner:
            self.unlocked_until, self.bio_fails = now + UNLOCK_SECONDS, 0
            return dict(result="match", message="Fingerprint matched on the card. The chip is live for 15 seconds. Tap it at the terminal.")
        self.bio_fails += 1
        if self.bio_fails >= BIO_MAX_FAILURES:
            self.bio_locked_until, self.bio_fails = now + BIO_LOCK_SECONDS, 0
            return dict(result="lockout", message="Third wrong finger. The sensor locks for 30 seconds, so a thief can't keep trying.")
        return dict(result="fail", message=f"Fingerprint rejected. That isn't the owner. {BIO_MAX_FAILURES - self.bio_fails} tries left before lockout.")

    # ------------------------------------------------------------------ bank
    def _record(self, channel: str, amount: float, ok: bool, reason: str, hour: int, block: bool = False) -> Entry:
        e = Entry(t=self.clock(), channel=channel, amount=round(float(amount), 2), ok=ok, reason=reason, block=block, hour=hour)
        self.ledger.append(e)
        self._monitor()
        return e

    def tap(self, amount: float, hour: int) -> Entry:
        left = self.unlocked_until - self.clock()
        if left <= 0:
            return self._record("In-Store", amount, False, "Chip locked: fingerprint required", hour, block=True)
        self.done.add(1)
        return self._record("In-Store", amount, True, f"Fingerprint verified, {int(left + 0.999)}s left", hour)

    def pay_online(self, pan: str, cvv: str, amount: float, hour: int) -> dict:
        """Check an online payment. Returns the logged entry, or a pending approval if the CVV is good."""
        now = self.clock()
        if self.pending:
            return dict(status="busy", message="A purchase is already waiting for approval.")
        if "".join(ch for ch in pan if ch.isdigit()) != CARD_PAN:
            return dict(status="invalid", message="Card number not recognised.")
        if now < self.online_blocked_until:
            left = int(self.online_blocked_until - now + 0.999)
            e = self._record("Online", amount, False, "Online payments blocked after 3 wrong CVVs", hour, block=True)
            return dict(status="declined", entry=e, message=f"Too many wrong codes. Online payments paused for {left}s.")
        if not (len(cvv) == CVV_DIGITS and cvv.isdigit()):
            return dict(status="invalid", message="The CVV is 3 digits.")
        step = self.step()
        if secrets.compare_digest(cvv, self.code_at(step)):
            if step in self.used_steps:
                self.cvv_fails += 1
                e = self._record("Online", amount, False, "CVV already used (replay blocked)", hour, block=True)
                return dict(status="declined", entry=e, message="That code was already used. Each code works once.")
            self.used_steps.add(step)
            self.cvv_fails = 0
            self.pending = Pending(amount=round(float(amount), 2), hour=hour, expires=now + PUSH_SECONDS)
            return dict(status="pending", message="CVV is valid. Approve the purchase to finish.")
        self.cvv_fails += 1
        stale = any(secrets.compare_digest(cvv, self.code_at(step - k)) for k in range(1, STALE_LOOKBACK_STEPS + 1))
        reason = "CVV expired: matches an earlier window (likely leaked data)" if stale else "Incorrect CVV"
        if self.cvv_fails >= CVV_MAX_FAILURES:
            self.online_blocked_until, self.cvv_fails = now + CVV_LOCK_SECONDS, 0
            reason += "; online payments paused 60s"
        e = self._record("Online", amount, False, reason, hour, block=True)
        return dict(status="declined", entry=e, message=reason, stale=stale)

    def decide(self, decision: str) -> Entry | None:
        """The owner's answer to a pending approval: approve, badfinger, deny or timeout."""
        p = self.pending
        if p is None:
            return None
        self.pending = None
        if decision == "approve":
            self.done.add(2)
            return self._record("Online", p.amount, True, "CVV valid, approved with fingerprint", p.hour)
        if decision == "badfinger":
            return self._record("Online", p.amount, False, "Approval failed fingerprint check", p.hour, block=True)
        if decision == "timeout":
            return self._record("Online", p.amount, False, "No answer to approval request", p.hour)
        return self._record("Online", p.amount, False, "Owner denied the purchase", p.hour, block=True)

    def expire_pending(self) -> None:
        if self.pending and self.clock() >= self.pending.expires:
            self.decide("timeout")

    # ------------------------------------------------------------------ attacks (mission 03)
    def attack_replay(self, hour: int) -> dict:
        old = self.code_at(self.step() - 2)
        res = self.pay_online(CARD_PAN, old, 249.99, hour)
        self.done.add(3)
        return dict(code=old, **res)

    def attack_card_testing(self, hour: int) -> list[Entry]:
        self.unlocked_until = 0.0
        self.done.add(3)
        return [self.tap(9.99 + i, hour) for i in range(3)]

    def attack_guess(self, hour: int, rng: random.Random | None = None) -> list[dict]:
        rng = rng or random.SystemRandom()
        real, out = self.cvv_now(), []
        for _ in range(3):
            g = real
            while g == real:
                g = f"{rng.randrange(1000):03d}"
            out.append(dict(code=g, **self.pay_online(CARD_PAN, g, 19.99, hour)))
        self.done.add(3)
        return out

    # ------------------------------------------------------------------ fraud AI (mission 04)
    @staticmethod
    def judge(amount: float, hour: int, online: bool) -> dict:
        s = fraud.score(amount, hour, online)
        lof, limit = fraud.lof_details(amount, hour, online)
        return dict(z=s.robust_z, lof=round(lof, 3), lof_limit=round(limit, 3), outlier=s.robust_z > fraud.ROBUST_Z_LIMIT,
                    pattern=s.lof_flagged, flagged=s.flagged, reason=s.reason)

    def judge_preset(self, amount: float, hour: int, online: bool) -> dict:
        j = self.judge(amount, hour, online)
        if j["pattern"] and not j["outlier"] and hour < 6:   # caught the 3 AM lunch: mission complete
            self.done.add(4)
        return j

    # ------------------------------------------------------------------ fraud monitor
    def _monitor(self) -> None:
        found: list[Alert] = []
        for ch in ("In-Store", "Online"):
            blocks = [(i, e) for i, e in enumerate(self.ledger) if e.block and e.channel == ch]
            for n, (i, e) in enumerate(blocks):
                in_window = sum(1 for _, x in blocks[: n + 1] if e.t - x.t <= BURST_SECONDS)
                if in_window == BURST_COUNT:
                    found.append(Alert(f"burst-{i}", "high", f"3 blocked {ch.lower()} attempts in 5 minutes",
                                       "Repeated failures in a short time look like someone testing a stolen card."))
        for i, e in enumerate(self.ledger):
            if "expired" in e.reason:
                found.append(Alert(f"leak-{i}", "high", f"Stolen card data used online (${e.amount:,.2f})",
                                   "Someone entered an old CVV, so the card details were probably leaked."))
            if "denied" in e.reason:
                found.append(Alert(f"deny-{i}", "high", f"Purchase rejected by the owner (${e.amount:,.2f})",
                                   "The CVV was right but the owner said it wasn't them. Their current code may have been phished."))
            if e.ok and f"z-{i}" not in self._alert_keys and f"lof-{i}" not in self._alert_keys:
                s = fraud.score(e.amount, e.hour, e.channel == "Online")
                if s.robust_z > fraud.ROBUST_Z_LIMIT:
                    found.append(Alert(f"z-{i}", "med", f"Unusually large {e.channel.lower()} purchase (${e.amount:,.2f})",
                                       f"Robust z-score {s.robust_z:.1f}, far above the owner's normal range."))
                elif s.lof_flagged:
                    found.append(Alert(f"lof-{i}", "med", f"Unusual purchase pattern (${e.amount:,.2f} at {e.hour}:00)",
                                       "The model rates this amount, time and channel as unlike the owner's history."))
        for a in found:
            if a.key not in self._alert_keys:
                self._alert_keys.add(a.key)
                a.t = self.clock()
                self.alerts.insert(0, a)

    # ------------------------------------------------------------------ what the page shows
    def stats(self) -> dict:
        ok = [e for e in self.ledger if e.ok]
        return dict(attempts=len(self.ledger), approved=len(ok), blocked=sum(e.block for e in self.ledger),
                    alerts=len(self.alerts), volume=round(sum(e.amount for e in ok), 2))

    def state(self, since_alert: int = 0) -> dict:
        self.expire_pending()
        now = self.clock()
        return dict(
            unlock_left=max(0.0, round(self.unlocked_until - now, 2)),
            bio_lock_left=max(0.0, round(self.bio_locked_until - now, 2)),
            online_block_left=max(0.0, round(self.online_blocked_until - now, 2)),
            cvv=self.cvv_now(),
            cvv_left=CVV_STEP_SECONDS - int(now) % CVV_STEP_SECONDS,
            pending=dict(amount=self.pending.amount, left=round(self.pending.expires - now, 1)) if self.pending else None,
            stats=self.stats(),
            ledger=[e.public() for e in reversed(self.ledger)],
            alerts=[asdict(a) for a in self.alerts],
            done=sorted(self.done),
        )


class SessionStore:
    """Labs kept in memory, one per browser. Idle labs are dropped after ``ttl`` seconds."""

    def __init__(self, ttl: float = 2 * 3600, max_sessions: int = 5000):
        self.ttl, self.max = ttl, max_sessions
        self._labs: dict[str, tuple[CardLab, float]] = {}
        self._lock = threading.Lock()

    def get(self, sid: str | None) -> tuple[str, CardLab]:
        now = time.time()
        with self._lock:
            if sid and sid in self._labs:
                lab = self._labs[sid][0]
                self._labs[sid] = (lab, now)
                return sid, lab
            if len(self._labs) >= self.max:
                self._evict(now)
            sid = secrets.token_urlsafe(24)
            lab = CardLab()
            self._labs[sid] = (lab, now)
            return sid, lab

    def _evict(self, now: float) -> None:
        stale = [k for k, (_, seen) in self._labs.items() if now - seen > self.ttl]
        for k in stale:
            del self._labs[k]
        if len(self._labs) >= self.max:          # still full: drop the least recently used
            for k, _ in sorted(self._labs.items(), key=lambda kv: kv[1][1])[: len(self._labs) - self.max + 1]:
                del self._labs[k]

    def __len__(self) -> int:
        return len(self._labs)
