"""Request signing, replay protection, rate limiting and tokenization."""

import hashlib
import hmac
import threading
import time
from collections import OrderedDict

SIGNATURE_HEADERS = ("X-Client-Id", "X-Timestamp", "X-Nonce", "X-Signature")


def canonical_request(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path, timestamp, nonce, body_hash]).encode()


def sign_request(
    secret: bytes, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> str:
    message = canonical_request(method, path, timestamp, nonce, body)
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def signatures_match(expected: str, given: str) -> bool:
    return hmac.compare_digest(expected.encode(), given.encode())


class NonceCache:
    """Remembers recent nonces so a captured request can't be sent twice."""

    def __init__(self, ttl_seconds: int, max_size: int = 100_000):
        self.ttl = ttl_seconds
        self.max_size = max_size
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def use(self, key: str) -> bool:
        """Return True the first time a nonce is seen, False on a replay."""
        now = time.monotonic()
        with self._lock:
            while self._seen and next(iter(self._seen.values())) < now - self.ttl:
                self._seen.popitem(last=False)
            if key in self._seen:
                return False
            if len(self._seen) >= self.max_size:
                self._seen.popitem(last=False)
            self._seen[key] = now
            return True


class RateLimiter:
    """Token bucket per key (client id, card, ...)."""

    def __init__(self, per_minute: int):
        self.rate = per_minute / 60.0
        self.capacity = float(per_minute)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def blocked(self, key: str) -> bool:
        """True if the bucket is empty, without using a token."""
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            return min(self.capacity, tokens + (now - last) * self.rate) < 1

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            return True


def tokenize(key: bytes, value: str) -> str:
    # keyed HMAC, not a plain hash - card numbers are few enough to brute-force a plain hash
    return "tok_" + hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:16]


def card_cryptogram(
    card_key: bytes, pan: str, amount_cents: int, merchant_id: str, atc: int
) -> str:
    """What the card's chip signs for an in-store payment (a simplified EMV ARQC).

    The chip only produces this after a fingerprint match. The bank recomputes it
    and checks the transaction counter (ATC) only ever goes up, so an old
    cryptogram can't be replayed.
    """
    message = f"{pan}|{amount_cents}|{merchant_id}|{atc}".encode()
    return hmac.new(card_key, message, hashlib.sha256).hexdigest()


def approval_signature(device_key: bytes, approval_id: str, decision: str) -> str:
    """What the cardholder's device signs after the user confirms with their fingerprint."""
    message = f"{approval_id}|{decision}".encode()
    return hmac.new(device_key, message, hashlib.sha256).hexdigest()
