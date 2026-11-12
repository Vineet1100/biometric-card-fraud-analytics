"""HTTP API for the bank.

Every endpoint except /healthz needs a signed request (see security.py) from a
client that has the right scope. Authentication runs before the body is parsed,
so an unauthenticated caller learns nothing about the request format.
"""

import json
import logging
import os
import time
from decimal import Decimal
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import fraud
from .config import Client, Settings, load_settings
from .core import APPROVED, PENDING, Bank
from .security import SIGNATURE_HEADERS, NonceCache, RateLimiter, sign_request, signatures_match

MONEY = {"gt": 0, "le": 10_000, "max_digits": 7, "decimal_places": 2}
MERCHANT_ID = r"^[a-z0-9][a-z0-9-]{2,39}$"  # also keeps free text out of alerts
HEX_64 = r"^[0-9a-f]{64}$"
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class InStoreRequest(Strict):
    pan: str = Field(pattern=r"^\d{12,19}$")
    amount: Decimal = Field(**MONEY)
    merchant_id: str = Field(pattern=MERCHANT_ID)
    atc: int = Field(ge=0, le=2**31 - 1)
    cryptogram: str = Field(pattern=HEX_64)


class OnlineRequest(Strict):
    pan: str = Field(pattern=r"^\d{12,19}$")
    cvv: str = Field(pattern=r"^\d{3}$")
    amount: Decimal = Field(**MONEY)
    merchant_id: str = Field(pattern=MERCHANT_ID)


class DecisionRequest(Strict):
    decision: Literal["approve", "deny"]
    signature: str = Field(pattern=HEX_64)


class ScoreRequest(Strict):
    amount: Decimal = Field(**MONEY)
    hour: int = Field(ge=0, le=23)
    channel: Literal["in_store", "online"]


def _audit_logger(path: str) -> logging.Logger:
    logger = logging.getLogger(f"bank.audit.{path}")
    if not logger.handlers:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)  # owner-only
        os.close(fd)
        handler = logging.FileHandler(path)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def _result(code: str) -> dict:
    return {"response_code": code, "message": "approved" if code == APPROVED else "declined"}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    bank = Bank(settings)
    nonces = NonceCache(ttl_seconds=settings.max_clock_skew_seconds * 2)
    limiter = RateLimiter(settings.requests_per_minute)
    failed_auth = RateLimiter(per_minute=20)  # per source address
    audit = _audit_logger(settings.audit_log_path)
    dev = settings.env == "dev"

    app = FastAPI(
        title="Biometric card bank API",
        docs_url="/docs" if dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if dev else None,
    )
    app.state.bank = bank

    def log(client: str, endpoint: str, **fields) -> None:
        # card numbers are tokenized; CVVs, cryptograms and signatures are never logged
        record = {"ts": time.time(), "client": client, "endpoint": endpoint, **fields}
        audit.info(json.dumps(record, default=str))

    @app.middleware("http")
    async def guard(request: Request, call_next):
        length = request.headers.get("content-length", "0")
        if not length.isdigit() or int(length) > settings.max_body_bytes:
            return JSONResponse({"error": "request too large"}, status_code=413)
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(Exception)
    async def hide_errors(request: Request, exc: Exception):
        # never leak stack traces or internals to the caller
        log("-", request.url.path, error=type(exc).__name__)
        return JSONResponse({"error": "internal error"}, status_code=500)

    async def authenticate(request: Request, scope: str) -> tuple[Client, bytes]:
        source = request.client.host if request.client else "unknown"
        if failed_auth.blocked(source):
            raise HTTPException(429, "too many requests")

        def reject(reason: str):
            failed_auth.allow(source)
            log(request.headers.get("X-Client-Id", "-")[:64], request.url.path, auth_failed=reason)
            return HTTPException(401, "unauthorized")

        client_id, timestamp, nonce, signature = (
            request.headers.get(h, "") for h in SIGNATURE_HEADERS
        )
        body = await request.body()
        if len(body) > settings.max_body_bytes:
            raise HTTPException(413, "request too large")
        client = settings.clients.get(client_id)
        if client is None:
            raise reject("unknown client")
        if (
            not timestamp.isdigit()
            or abs(time.time() - int(timestamp)) > settings.max_clock_skew_seconds
        ):
            raise reject("stale or missing timestamp")
        if not 16 <= len(nonce) <= 128:
            raise reject("bad nonce")
        expected = sign_request(
            client.secret, request.method, request.url.path, timestamp, nonce, body
        )
        if not signatures_match(expected, signature):
            raise reject("bad signature")
        if not nonces.use(f"{client_id}:{nonce}"):
            raise reject("replayed request")
        if not limiter.allow(client_id):
            raise HTTPException(429, "too many requests")
        if scope not in client.scopes:
            log(client_id, request.url.path, auth_failed=f"missing scope {scope}")
            raise HTTPException(403, "forbidden")
        return client, body

    def parse(model, body: bytes):
        try:
            return model.model_validate_json(body)
        except ValidationError:
            raise HTTPException(422, "invalid request") from None

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.post("/v1/authorize/in-store")
    async def in_store(request: Request):
        client, body = await authenticate(request, "authorize:in_store")
        req = parse(InStoreRequest, body)
        code, tx = bank.authorize_in_store(
            req.pan, req.amount, req.merchant_id, req.atc, req.cryptogram
        )
        log(
            client.id,
            "in-store",
            card_ref=tx.card_ref,
            merchant=req.merchant_id,
            amount=req.amount,
            code=code,
            reason=tx.reason,
        )
        return _result(code)

    @app.post("/v1/authorize/online")
    async def online(request: Request):
        client, body = await authenticate(request, "authorize:online")
        req = parse(OnlineRequest, body)
        code, approval, tx = bank.authorize_online(req.pan, req.cvv, req.amount, req.merchant_id)
        if code == PENDING:
            log(
                client.id,
                "online",
                card_ref=approval.card_ref,
                merchant=req.merchant_id,
                amount=req.amount,
                code=code,
                approval_id=approval.id,
            )
            return {
                "response_code": PENDING,
                "message": "waiting for cardholder approval",
                "approval_id": approval.id,
            }
        log(
            client.id,
            "online",
            card_ref=tx.card_ref,
            merchant=req.merchant_id,
            amount=req.amount,
            code=code,
            reason=tx.reason,
        )
        return _result(code)

    @app.get("/v1/approvals")
    async def pending_approvals(request: Request):
        await authenticate(request, "approvals:decide")
        now = time.monotonic()
        return {
            "approvals": [
                {
                    "approval_id": a.id,
                    "amount": str(a.amount),
                    "merchant_id": a.merchant_id,
                    "expires_in": max(0, round(a.expires_at - now)),
                }
                for a in bank.pending()
            ]
        }

    @app.post("/v1/approvals/{approval_id}")
    async def decide(approval_id: str, request: Request):
        client, body = await authenticate(request, "approvals:decide")
        req = parse(DecisionRequest, body)
        result = bank.decide(approval_id, req.decision, req.signature)
        if result is None:
            raise HTTPException(404, "not found")
        code, tx = result
        log(
            client.id,
            "approval",
            card_ref=tx.card_ref,
            merchant=tx.merchant_id,
            amount=tx.amount,
            code=code,
            reason=tx.reason,
        )
        return _result(code)

    @app.post("/v1/fraud/score")
    async def score(request: Request):
        client, body = await authenticate(request, "fraud:score")
        req = parse(ScoreRequest, body)
        result = fraud.score(float(req.amount), req.hour, req.channel == "online")
        log(client.id, "score", amount=req.amount, flagged=result.flagged)
        return {
            "flagged": result.flagged,
            "reason": result.reason,
            "robust_z": result.robust_z,
            "pattern_flagged": result.lof_flagged,
        }

    @app.get("/v1/alerts")
    async def alerts(request: Request, limit: int = Query(20, ge=1, le=100)):
        await authenticate(request, "alerts:read")
        return {"alerts": list(reversed(bank.alerts))[:limit]}

    @app.get("/v1/stats")
    async def stats(request: Request):
        await authenticate(request, "stats:read")
        return bank.stats()

    return app
