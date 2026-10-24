"""
Biometric payment card simulator with a dynamic CVV and a fraud monitor.

Three parties run in one Streamlit app:
- the card: fingerprint sensor (match-on-card) and an e-ink screen showing a TOTP CVV
- two merchants: an in-store terminal and an online checkout
- the bank: approves or declines each attempt, keeps the log, and looks for fraud patterns

On a Mac with Touch ID the fingerprint sensor and the purchase approval use the real
Touch ID sensor. Everywhere else they fall back to a simulation.

Simplifications compared with a real card:
- a locked card wouldn't send a "locked" flag; the secure element just refuses to
  produce the EMV cryptogram, so the terminal has nothing valid to send
- the TOTP secret would live in the card's secure element and the bank's HSM,
  not in session state
- merchants only get generic decline codes; the detailed reasons here are what
  the bank's own fraud team would see

Run with: streamlit run app.py
"""

import contextlib
import hashlib
import hmac
import math
import platform
import random
import secrets
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import pyotp
import streamlit as st

# optional - the app still runs without these, it just skips the ML model / chart
try:
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False
try:
    import plotly.graph_objects as go
except ImportError:
    go = None

# macOS only, falls back to the simulated sensor elsewhere
try:
    import LocalAuthentication  # from pyobjc-framework-LocalAuthentication
except ImportError:
    LocalAuthentication = None

# --- Configuration ---
UNLOCK_WINDOW_SECONDS = 15  # how long the chip stays active after a match
CVV_STEP_SECONDS = 120  # each CVV lasts 2 min (RFC 6238 default is 30s)
CVV_DIGITS = 3
MATCH_THRESHOLD = 0.80  # min score to accept a fingerprint
MAX_BIO_FAILURES = 3  # failed scans before the sensor locks out
BIO_LOCKOUT_SECONDS = 30
MAX_CVV_FAILURES = 3  # bad online CVVs before the bank blocks card-not-present
CVV_LOCKOUT_SECONDS = 60
STALE_LOOKBACK_STEPS = 4  # how many old windows to check when labelling a CVV as expired

CARD_PAN = "4111111111111111"  # Visa test number
CARD_HOLDER = "ALEX MORGAN"
CARD_EXPIRY = "12/29"
ISSUER = "NOVA BANK"

ENROLLED_FINGER = "Enrolled finger (cardholder)"
UNKNOWN_FINGER = "Unknown finger (thief)"

SENSOR_TOUCH_ID = "Touch ID (this Mac)"
SENSOR_SIMULATED = "Simulated"
TOUCH_ID_TIMEOUT_SECONDS = 60


# --- Real fingerprint: macOS Touch ID ---
# Touch ID works like match-on-card: the template and the comparison stay in the
# Secure Enclave and we only get back yes/no.
def _biometric_policy() -> int:
    return getattr(LocalAuthentication, "LAPolicyDeviceOwnerAuthenticationWithBiometrics", 1)


@st.cache_resource
def touch_id_available() -> bool:
    if LocalAuthentication is None:
        return False
    try:
        context = LocalAuthentication.LAContext.new()
        ok, _error = context.canEvaluatePolicy_error_(_biometric_policy(), None)
        return bool(ok)
    except Exception:
        return False


# LAError codes (LocalAuthentication/LAError.h)
LA_USER_CANCEL = -2  # user clicked Cancel
LA_SYSTEM_CANCEL = -4  # macOS cancelled (e.g. another app took focus)
LA_BIOMETRY_LOCKOUT = -8  # too many failed attempts; macOS wants the password


def touch_id_authenticate(reason: str) -> tuple[bool, int | None]:
    """Show the Touch ID prompt and block until it answers. Returns (matched, error_code)."""
    context = LocalAuthentication.LAContext.new()
    # no password fallback - the card only takes a fingerprint
    context.setLocalizedFallbackTitle_("")

    done = threading.Event()
    result = {"ok": False, "code": None}

    def reply(success, error):
        result["ok"] = bool(success)
        result["code"] = int(error.code()) if error is not None else None
        done.set()

    context.evaluatePolicy_localizedReason_reply_(_biometric_policy(), reason, reply)
    # the reply comes back on another thread; time out so the app can't hang
    if not done.wait(TOUCH_ID_TIMEOUT_SECONDS):
        context.invalidate()
        return False, None
    return result["ok"], result["code"]


# --- Push approval for online payments (like a Duo push) ---
# The dynamic CVV doesn't help if a phishing page gets the *current* code, so after
# the CVV checks out the bank also asks the cardholder to approve the purchase.
# The prompt shows merchant + amount so people approve a specific payment, not a
# vague "is this you?" (which is what push-fatigue attacks rely on).
PUSH_TIMEOUT_SECONDS = 60
PUSH_CHANNEL_MAC = "Notification on this Mac"
PUSH_CHANNEL_IN_APP = "On this page"
MERCHANT_NAME = "Northwind Electronics"


@st.cache_resource
def mac_push_available() -> bool:
    return platform.system() == "Darwin" and shutil.which("osascript") is not None


def _applescript_text(text: str) -> str:
    return text.replace("\\", "").replace('"', "'")


def send_mac_push(amount: float) -> tuple[str, str]:
    """Approve/deny alert via osascript. Returns ("approve"|"deny"|"timeout"|"error", detail)."""
    merchant = _applescript_text(MERCHANT_NAME)
    lines = [
        f"Merchant: {merchant}",
        f"Amount: ${amount:,.2f} CAD",
        f"Card ending {CARD_PAN[-4:]}",
        f"Time: {datetime.now():%H:%M:%S}",
        "",
        "If you did not start this purchase, click Deny.",
    ]
    message = '" & return & "'.join(_applescript_text(line) for line in lines)
    script = f"""
display notification "Approve ${amount:,.2f} at {merchant}?" with title "{ISSUER}" subtitle "Purchase approval request" sound name "Glass"
activate
set r to display alert "{ISSUER}: approve this purchase?" message ("{message}") buttons {{"Deny", "Approve"}} giving up after {PUSH_TIMEOUT_SECONDS}
if gave up of r then return "timeout"
return button returned of r
"""
    try:
        out = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=PUSH_TIMEOUT_SECONDS + 15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "error", f"could not show the prompt ({exc.__class__.__name__})"
    answer = out.stdout.strip().lower()
    if out.returncode != 0:
        return "error", out.stderr.strip()[:120] or "osascript failed"
    if answer in ("approve", "deny", "timeout"):
        return answer, ""
    return "error", f"unexpected answer {answer!r}"


def verify_push_approval(amount: float) -> tuple[bool, str]:
    # a click could come from anyone at the laptop, so ask for Touch ID too
    if not touch_id_available():
        return True, "approved"
    ok, _code = touch_id_authenticate(f"approve ${amount:,.2f} at {MERCHANT_NAME}")
    return (
        (True, "approved with Touch ID") if ok else (False, "Touch ID check on the approval failed")
    )


def finish_push(decision: str, detail: str = "") -> dict:
    ss = st.session_state
    pending = ss.pending_push
    ss.pending_push = None
    amount, pan = pending["amount"], pending["pan"]

    if decision == "approve":
        ok, how = (
            verify_push_approval(amount)
            if pending["channel"] == PUSH_CHANNEL_MAC
            else (True, "approved")
        )
        if ok:
            entry = record(
                "Online", amount, pan, True, f"Dynamic CVV valid; push {how} by cardholder"
            )
        else:
            entry = record("Online", amount, pan, False, how, security_block=True)
    elif decision == "deny":
        entry = record(
            "Online",
            amount,
            pan,
            False,
            "Cardholder denied the push: purchase not recognised (fraud)",
            security_block=True,
        )
    elif decision == "timeout":
        entry = record(
            "Online", amount, pan, False, f"No answer to the push within {PUSH_TIMEOUT_SECONDS}s"
        )
    else:
        entry = record(
            "Online",
            amount,
            pan,
            False,
            f"Could not reach the cardholder's device ({detail}); declined to be safe",
        )
    ss.online_result = entry
    return entry


# --- State management ---
# Streamlit reruns the script on every interaction, so anything that has to stick
# around lives in session_state.
def init_state() -> None:
    ss = st.session_state
    if ss.get("initialized"):
        return

    # card and bank share one secret and each work out the CVV from it + the time
    shared_secret = pyotp.random_base32()
    ss.card_secret = shared_secret
    ss.bank_secret = shared_secret

    ss.token_key = secrets.token_bytes(32)

    # monotonic clock so changing the system time can't stretch the unlock window
    ss.unlock_expires_at = 0.0
    ss.bio_failures = 0
    ss.bio_locked_until = 0.0
    ss.last_bio_result = None
    ss.sensor_mode = SENSOR_TOUCH_ID if touch_id_available() else SENSOR_SIMULATED

    ss.cvv_failures = 0
    ss.online_blocked_until = 0.0
    ss.used_cvv_steps = set()  # windows whose CVV was already used

    # sidebar settings
    ss.single_use_unlock = False
    ss.replay_protection = True
    ss.drift_grace = False
    ss.push_enabled = True
    ss.push_channel = PUSH_CHANNEL_MAC if mac_push_available() else PUSH_CHANNEL_IN_APP
    ss.pending_push = None
    ss.fraud_notify = True
    ss.demo_clock = CLOCK_REAL
    ss.alerted_keys = set()  # alerts already shown, so each fires once

    ss.pos_result = None
    ss.online_result = None
    ss.ledger = []
    ss.co_pan = ""
    ss.co_cvv = ""

    ss.initialized = True


# --- Card side: Match-on-Card biometrics and the e-ink CVV ---
def card_totp() -> pyotp.TOTP:
    # CVV = truncate(HMAC-SHA1(secret, unix_time // step)) mod 10^3  (RFC 6238)
    return pyotp.TOTP(st.session_state.card_secret, digits=CVV_DIGITS, interval=CVV_STEP_SECONDS)


def unlock_remaining() -> float:
    return max(0.0, st.session_state.unlock_expires_at - time.monotonic())


def match_on_card_score(finger: str) -> float:
    # fake matcher score: real matchers compare minutiae and return a similarity,
    # so the enrolled finger lands high and anyone else lands low
    if finger == ENROLLED_FINGER:
        return random.uniform(0.86, 0.99)
    return random.uniform(0.05, 0.45)


def scan_fingerprint() -> None:
    ss = st.session_state
    now = time.monotonic()

    # lock out after repeated failures so someone can't just try finger after finger
    if now < ss.bio_locked_until:
        wait = math.ceil(ss.bio_locked_until - now)
        ss.last_bio_result = (
            "locked",
            f"Sensor locked after {MAX_BIO_FAILURES} failed scans. Try again in {wait}s.",
        )
        return

    if ss.get("sensor_mode") == SENSOR_TOUCH_ID and touch_id_available():
        ok, code = touch_id_authenticate(f"unlock your {ISSUER} card to pay")
        if ok:
            detail = "Touch ID verified by the Secure Enclave"
        elif code in (LA_USER_CANCEL, LA_SYSTEM_CANCEL):
            # cancelling isn't an attack, don't count it
            ss.last_bio_result = ("no_match", "Scan cancelled. Card stays locked.")
            return
        elif code == LA_BIOMETRY_LOCKOUT:
            ss.bio_locked_until = time.monotonic() + BIO_LOCKOUT_SECONDS
            ss.last_bio_result = (
                "locked",
                "macOS locked Touch ID after too many failed fingers. "
                "Unlock your Mac with its password to re-enable it.",
            )
            return
        elif code is None and not ok:
            ss.last_bio_result = (
                "no_match",
                "No fingerprint within " f"{TOUCH_ID_TIMEOUT_SECONDS}s. Card stays locked.",
            )
            return
        else:
            detail = "Touch ID did not recognise that finger"
    else:
        score = match_on_card_score(ss.get("finger_choice", ENROLLED_FINGER))
        ok = score >= MATCH_THRESHOLD
        detail = f"score {score:.2f}"

    # start the window when the scan finished, not when the button was pressed
    now = time.monotonic()
    if ok:
        ss.unlock_expires_at = now + UNLOCK_WINDOW_SECONDS
        ss.bio_failures = 0
        ss.last_bio_result = (
            "match",
            f"Fingerprint matched ({detail}). Chip active for {UNLOCK_WINDOW_SECONDS}s.",
        )
    else:
        ss.bio_failures += 1
        if ss.bio_failures >= MAX_BIO_FAILURES:
            ss.bio_locked_until = now + BIO_LOCKOUT_SECONDS
            ss.bio_failures = 0
            ss.last_bio_result = (
                "locked",
                f"No match ({detail}). Too many failures: "
                f"sensor locked for {BIO_LOCKOUT_SECONDS}s.",
            )
        else:
            left = MAX_BIO_FAILURES - ss.bio_failures
            ss.last_bio_result = (
                "no_match",
                f"No match ({detail}). {left} attempt(s) left before lockout.",
            )


# --- Bank side: tokenization, ledger, authorization ---
def pan_token(pan: str) -> str:
    # keyed HMAC, not plain SHA-256 - there are few enough card numbers to brute-force a hash
    if not pan:
        return "-"
    digest = hmac.new(st.session_state.token_key, pan.encode(), hashlib.sha256).hexdigest()
    return f"tok_{digest[:10]}"


def luhn_valid(pan: str) -> bool:
    if not pan.isdigit() or not 12 <= len(pan) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(pan)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def record(
    channel: str, amount: float, pan: str, approved: bool, reason: str, security_block: bool = False
) -> dict:
    entry = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Type": channel,
        "Amount": round(float(amount), 2),
        "Card ref": pan_token(pan),
        "Status": "APPROVED" if approved else "DECLINED",
        "Reason": reason,
        "Security block": security_block,
        # used by the anomaly model; the "3 AM" setting overrides it
        "Hour": (
            NIGHT_HOUR if st.session_state.get("demo_clock") == CLOCK_NIGHT else datetime.now().hour
        ),
    }
    st.session_state.ledger.append(entry)
    return entry


def authorize_in_store(amount: float) -> dict:
    ss = st.session_state
    if amount <= 0:
        return record("In-Store", amount, CARD_PAN, False, "Invalid amount")

    # check expiry at the moment of the tap - the on-screen countdown doesn't matter
    remaining = unlock_remaining()
    if remaining <= 0:
        return record(
            "In-Store",
            amount,
            CARD_PAN,
            False,
            "Card chip locked - Biometric verification required",
            security_block=True,
        )

    if ss.single_use_unlock:
        ss.unlock_expires_at = 0.0
    return record(
        "In-Store",
        amount,
        CARD_PAN,
        True,
        f"Biometric verified on card; tapped with {remaining:.1f}s left in window",
    )


def authorize_online(pan_input: str, cvv_input: str, amount: float) -> dict:
    ss = st.session_state
    pan = "".join(ch for ch in pan_input if ch.isdigit())
    cvv = cvv_input.strip()
    now_mono = time.monotonic()

    if ss.pending_push:
        return {
            "Status": "PENDING",
            "Amount": round(float(amount), 2),
            "Reason": "Another payment is waiting to be confirmed. Finish or cancel it first.",
        }
    if amount <= 0:
        return record("Online", amount, pan, False, "Invalid amount")
    if not luhn_valid(pan):
        return record("Online", amount, pan, False, "Invalid card number (failed Luhn check)")
    if pan != CARD_PAN:
        return record("Online", amount, pan, False, "Card not issued by this bank")

    # only 1000 possible CVVs, so without a limit a bot could try them all in one window
    if now_mono < ss.online_blocked_until:
        wait = math.ceil(ss.online_blocked_until - now_mono)
        return record(
            "Online",
            amount,
            pan,
            False,
            f"Online payments blocked after {MAX_CVV_FAILURES} bad CVVs ({wait}s left)",
            security_block=True,
        )

    if not (cvv.isdigit() and len(cvv) == CVV_DIGITS):
        return record("Online", amount, pan, False, f"CVV must be {CVV_DIGITS} digits")

    bank_totp = pyotp.TOTP(ss.bank_secret, digits=CVV_DIGITS, interval=CVV_STEP_SECONDS)
    now = time.time()
    current_step = int(now // CVV_STEP_SECONDS)

    # drift grace also accepts the previous window, in case it changed mid-typing
    accepted_steps = [current_step, current_step - 1] if ss.drift_grace else [current_step]
    matched_step = None
    for step in accepted_steps:
        # constant-time compare
        if hmac.compare_digest(cvv, bank_totp.at(step * CVV_STEP_SECONDS)):
            matched_step = step
            break

    if matched_step is None:
        ss.cvv_failures += 1
        # just for the log message - a random guess can occasionally match an old window too
        stale = any(
            hmac.compare_digest(cvv, bank_totp.at((current_step - k) * CVV_STEP_SECONDS))
            for k in range(1, STALE_LOOKBACK_STEPS + 1)
            if (current_step - k) not in accepted_steps
        )
        window = f"{CVV_STEP_SECONDS // 60}-minute window"
        if stale:
            reason = f"CVV expired: matches an earlier {window} (likely leaked card data)"
        else:
            reason = "Incorrect CVV"
        if ss.cvv_failures >= MAX_CVV_FAILURES:
            ss.online_blocked_until = now_mono + CVV_LOCKOUT_SECONDS
            ss.cvv_failures = 0
            reason += f"; online payments blocked for {CVV_LOCKOUT_SECONDS}s"
        return record("Online", amount, pan, False, reason, security_block=True)

    # replay protection (RFC 6238 5.2): a code that already went through can't be reused
    ss.used_cvv_steps = {s for s in ss.used_cvv_steps if s >= current_step - 2}
    if ss.replay_protection and matched_step in ss.used_cvv_steps:
        ss.cvv_failures += 1
        return record(
            "Online",
            amount,
            pan,
            False,
            "CVV already used in this window (replay blocked)",
            security_block=True,
        )

    # burn the code now, even if the push gets denied later
    ss.used_cvv_steps.add(matched_step)
    ss.cvv_failures = 0

    if not ss.push_enabled:
        return record("Online", amount, pan, True, "Dynamic CVV valid for current time window")

    # hold the payment until the cardholder approves it
    ss.pending_push = {
        "amount": amount,
        "pan": pan,
        "channel": ss.push_channel,
        "expires_at": time.monotonic() + PUSH_TIMEOUT_SECONDS,
    }
    if ss.push_channel == PUSH_CHANNEL_MAC and mac_push_available():
        decision, detail = send_mac_push(amount)  # blocks until answered
        return finish_push(decision, detail)
    # otherwise the request shows on the page and the buttons call finish_push()
    return {
        "Status": "PENDING",
        "Amount": round(float(amount), 2),
        "Reason": "CVV valid. Approve or deny the request under the fingerprint sensor.",
    }


# --- Checkout helpers ---
def fill_from_card() -> None:
    st.session_state.co_pan = " ".join(CARD_PAN[i : i + 4] for i in range(0, 16, 4))
    st.session_state.co_cvv = card_totp().now()


def fill_leaked() -> None:
    # card data from a breach a few minutes ago - the CVV has since changed
    st.session_state.co_pan = CARD_PAN
    st.session_state.co_cvv = card_totp().at(time.time() - 2 * CVV_STEP_SECONDS)


# --- Styling ---
STYLE_PATH = Path(__file__).with_name("style.css")

FINGERPRINT_SVG = (
    '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" '
    'stroke-width="1.4" stroke-linecap="round" aria-hidden="true">'
    '<path d="M12 4a7 7 0 0 0-7 7v2"/><path d="M19 13v-2a7 7 0 0 0-3.5-6.06"/>'
    '<path d="M12 7.5a3.5 3.5 0 0 0-3.5 3.5v3a6 6 0 0 0 1.2 3.6"/>'
    '<path d="M15.5 11v2.5a9 9 0 0 1-.9 4"/><path d="M12 11v3.5a8 8 0 0 0 1.5 4.7"/></svg>'
)
CONTACTLESS_SVG = (
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#C9A55A" '
    'stroke-width="1.6" stroke-linecap="round" aria-hidden="true">'
    '<path d="M8 8.5a5 5 0 0 1 0 7"/><path d="M11.5 6a9 9 0 0 1 0 12"/>'
    '<path d="M15 3.5a13 13 0 0 1 0 17"/></svg>'
)


def html(markup: str) -> None:
    # flatten to one line, otherwise markdown treats indented HTML as a code block
    st.markdown(" ".join(line.strip() for line in markup.splitlines()), unsafe_allow_html=True)


def card_html(unlocked: bool, sensor_blocked: bool, cvv: str, cvv_left: int) -> str:
    pan_groups = " ".join(CARD_PAN[i : i + 4] for i in range(0, 16, 4))
    state = "blocked" if sensor_blocked else ("on" if unlocked else "")
    state_text = (
        "Sensor locked" if sensor_blocked else ("Chip active" if unlocked else "Chip locked")
    )
    bar_pct = cvv_left / CVV_STEP_SECONDS * 100
    return f"""
<div class="nv-stage"><div class="nv-wrap {state}"><div class="nv-card">
  <div class="nv-row">
    <div><div class="nv-brand">NOVA BANK</div><div class="nv-tier">Corporate</div></div>
    {CONTACTLESS_SVG}
  </div>
  <div class="nv-row" style="justify-content:flex-start;gap:12px">
    <div class="nv-chip {'' if unlocked else 'locked'}"></div>
    <span class="nv-state {state}"><span class="nv-dot"></span>{state_text}</span>
  </div>
  <div class="nv-pan">{pan_groups}</div>
  <div class="nv-row" style="align-items:flex-end">
    <div class="nv-meta">Cardholder<b>{CARD_HOLDER}</b>Valid thru<b>{CARD_EXPIRY}</b></div>
    <div class="nv-hw">
      <div class="nv-eink"><small>Dynamic CVV</small>
        <div class="nv-eink-cvv">{cvv}</div>
        <div class="nv-eink-bar"><span style="width:{bar_pct:.1f}%"></span></div></div>
      <div class="nv-fp {state}">{FINGERPRINT_SVG}</div>
    </div>
  </div>
</div></div></div>
"""


def ring_html(remaining: float, sensor_blocked: bool, lockout_left: float) -> str:
    r, size = 52, 118
    circumference = 2 * math.pi * r
    if sensor_blocked:
        frac, color, big, small = 1.0, "var(--stop)", f"{math.ceil(lockout_left)}", "s lockout"
    elif remaining > 0:
        frac, color, big, small = (
            remaining / UNLOCK_WINDOW_SECONDS,
            "var(--go)",
            f"{math.ceil(remaining)}",
            "s to pay",
        )
    else:
        frac, color, big, small = 0.0, "var(--brass)", "—", "locked"
    dash = circumference * frac
    return f"""
<div class="nv-ring">
  <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" aria-hidden="true">
    <circle cx="59" cy="59" r="{r}" fill="none" stroke="#22314B" stroke-width="7"/>
    <circle cx="59" cy="59" r="{r}" fill="none" stroke="{color}" stroke-width="7" stroke-linecap="round"
      stroke-dasharray="{dash:.1f} {circumference:.1f}"/>
  </svg>
  <div class="nv-ring-label"><b>{big}</b><span>{small}</span></div>
</div>
"""


# --- UI sections ---
@st.fragment(run_every=1)
def card_panel() -> None:
    # fragment so only the card refreshes every second, not the forms below
    ss = st.session_state
    remaining = unlock_remaining()
    unlocked = remaining > 0
    lockout_left = ss.bio_locked_until - time.monotonic()
    sensor_blocked = lockout_left > 0
    cvv = card_totp().now()
    cvv_left = CVV_STEP_SECONDS - int(time.time()) % CVV_STEP_SECONDS

    card_col, sensor_col = st.columns([1.15, 1], gap="large")
    with card_col:
        html(card_html(unlocked, sensor_blocked, cvv, cvv_left))
        st.caption(f"The CVV on the e-ink screen changes in {cvv_left // 60}:{cvv_left % 60:02d}.")

    with sensor_col:
        touch_id = ss.get("sensor_mode") == SENSOR_TOUCH_ID and touch_id_available()
        if unlocked:
            lead = "Card unlocked. Tap it at the terminal before the ring runs out."
        elif sensor_blocked:
            lead = "Too many failed scans. The sensor is resting before it accepts another finger."
        elif touch_id:
            lead = "Scan, then touch the Touch ID key on your Mac. A finger you never enrolled gets rejected."
        else:
            lead = "Scan your finger to unlock the chip for in-store payments."
        html(
            f'<div class="nv-sensor">{ring_html(remaining, sensor_blocked, lockout_left)}'
            f'<div><div class="nv-title">Fingerprint sensor</div><p>{lead}</p></div></div>'
        )

        if touch_id_available():
            st.radio(
                "Sensor", [SENSOR_TOUCH_ID, SENSOR_SIMULATED], key="sensor_mode", horizontal=True
            )
        if not touch_id:
            st.selectbox(
                "Finger on the sensor", [ENROLLED_FINGER, UNKNOWN_FINGER], key="finger_choice"
            )
        st.button(
            "Scan fingerprint",
            on_click=scan_fingerprint,
            type="primary",
            icon=":material/fingerprint:",
        )

        if ss.last_bio_result:
            kind, msg = ss.last_bio_result
            html(f'<div class="nv-note {kind}">{msg}</div>')

        phone_push_panel()


def phone_push_panel() -> None:
    # on-page approval request for when there's no Mac to pop up an alert
    ss = st.session_state
    pending = ss.pending_push
    if not pending or pending["channel"] != PUSH_CHANNEL_IN_APP:
        return
    left = pending["expires_at"] - time.monotonic()
    if left <= 0:
        finish_push("timeout")
        st.rerun(scope="app")
    with st.container(key="push_card"):
        html(
            f'<div class="nv-push"><b>{ISSUER}: approve this purchase?</b>'
            f'<div class="amt">${pending["amount"]:,.2f}</div>'
            f"<p>{MERCHANT_NAME}, card ending {CARD_PAN[-4:]}. Expires in {math.ceil(left)}s. "
            f"If you did not start this purchase, deny it.</p></div>"
        )
        c1, c2 = st.columns(2)
        if c1.button("Deny", key="push_deny", use_container_width=True):
            finish_push("deny")
            st.rerun(scope="app")
        if c2.button("Approve", key="push_approve", type="primary", use_container_width=True):
            finish_push("approve")
            st.rerun(scope="app")


def security_settings() -> None:
    st.header("Settings")
    st.markdown("#### Card")
    st.toggle(
        "One tap per fingerprint",
        key="single_use_unlock",
        help="Lock the chip again right after one in-store payment.",
    )
    st.markdown("#### Online payments")
    st.toggle("Ask me to approve each purchase", key="push_enabled")
    if mac_push_available():
        st.radio(
            "Send the approval request to",
            [PUSH_CHANNEL_MAC, PUSH_CHANNEL_IN_APP],
            key="push_channel",
        )
    st.toggle("Refuse a CVV that was already used", key="replay_protection")
    st.toggle(
        "Also accept the previous CVV",
        key="drift_grace",
        help="Gives shoppers extra time if the code changes while they type.",
    )
    st.markdown("#### Fraud monitor")
    if mac_push_available():
        st.toggle("Fraud alerts as Mac notifications", key="fraud_notify")
    st.radio(
        "Purchase time",
        [CLOCK_REAL, CLOCK_NIGHT],
        key="demo_clock",
        horizontal=True,
        help="Pretend purchases happen at 3 AM to see the ML model flag an unusual time.",
    )


def result_html(entry) -> str:
    if not entry:
        return ""
    status = entry["Status"]
    if status.endswith("PENDING"):
        kind, icon, title = "wait", "…", "Waiting for approval"
    elif status.endswith("APPROVED"):
        kind, icon, title = "ok", "✓", "Approved"
    else:
        kind, icon, title = "bad", "✕", "Declined"
    return (
        f'<div class="nv-result {kind}"><div class="ico">{icon}</div>'
        f'<div><b>{title}: ${entry["Amount"]:,.2f}</b><span>{entry["Reason"]}</span></div></div>'
    )


def lcd_html(entry) -> str:
    if not entry:
        return (
            '<div class="nv-lcd"><div class="big">TAP CARD</div>'
            '<div class="sub">Unlock the card with your fingerprint first.</div></div>'
        )
    approved = entry["Status"].endswith("APPROVED")
    word = "APPROVED" if approved else "DECLINED"
    return (
        f'<div class="nv-lcd {"" if approved else "declined"}">'
        f'<div class="big">{word} ${entry["Amount"]:,.2f}</div>'
        f'<div class="sub">{entry["Reason"]}</div></div>'
    )


def pos_terminal() -> None:
    with st.container(key="pos_device"):
        html(
            '<div class="nv-dev-head"><div class="nv-title">Corner Market</div><span>In-store terminal</span></div>'
        )
        screen = st.empty()
        with st.form("pos_form", border=False):
            amount = st.number_input(
                "Amount (CAD)", min_value=0.0, value=42.50, step=1.0, format="%.2f"
            )
            tapped = st.form_submit_button(
                "Tap card", type="primary", icon=":material/contactless:"
            )
        if tapped:
            st.session_state.pos_result = authorize_in_store(amount)
        with screen:
            html(lcd_html(st.session_state.pos_result))


def online_checkout() -> None:
    ss = st.session_state
    with st.container(key="shop_window"):
        html(
            '<div class="nv-browser"><div class="nv-lights"><i></i><i></i><i></i></div>'
            '<div class="nv-url"><b>Secure</b>&nbsp; northwind-electronics.ca/checkout</div></div>'
            f'<div class="nv-shop"><div class="nv-title">{MERCHANT_NAME}</div>'
            f"<p>The bank checks the CVV for the current {CVV_STEP_SECONDS // 60}-minute window, "
            "then asks you to approve the purchase.</p></div>"
        )
        b1, b2 = st.columns(2)
        b1.button(
            "Use my card",
            on_click=fill_from_card,
            icon=":material/credit_card:",
            help="Fill in the card number and the CVV shown on the card right now.",
        )
        b2.button(
            "Use leaked data",
            on_click=fill_leaked,
            icon=":material/warning:",
            help="Fill in card details stolen a few minutes ago, with an old CVV.",
        )
        with st.form("checkout_form", border=False):
            st.text_input("Card number", key="co_pan", placeholder="4111 1111 1111 1111")
            c1, c2 = st.columns([1, 2])
            c1.text_input("CVV", key="co_cvv", max_chars=CVV_DIGITS, placeholder="123")
            amount = c2.number_input(
                "Order total (CAD)", min_value=0.0, value=249.99, step=1.0, format="%.2f"
            )
            paid = st.form_submit_button("Pay now", type="primary", icon=":material/lock:")
        if paid:
            ss.online_result = authorize_online(ss.co_pan, ss.co_cvv, amount)
            in_app_push = ss.pending_push and ss.pending_push["channel"] == PUSH_CHANNEL_IN_APP
            if in_app_push:
                st.rerun()  # show the approval request straight away
        html(result_html(ss.online_result))


# --- Fraud monitor: pandas analysis of the audit log ---
# Looks across the whole log for patterns a single decline doesn't show:
#   1. bursts of blocked attempts (card testing)
#   2. replayed stolen card data (expired CVV)
#   3. purchases the cardholder denied
#   4. amounts far outside normal spending (robust z-score)
#   5. unusual amount/time/channel combinations (LOF model)
BURST_WINDOW = "5min"
BURST_THRESHOLD = 3  # security blocks in one channel within the window
ROBUST_Z_LIMIT = 3.5  # Iglewicz & Hoaglin cut-off
HISTORY_SIZE = 400  # simulated past transactions
MODEL_CONTAMINATION = 0.01
MODEL_NEIGHBOURS = 35

CLOCK_REAL = "Real time"
CLOCK_NIGHT = "3 AM (night)"
NIGHT_HOUR = 3

SEVERITY_ORDER = {"High": 0, "Medium": 1}


@st.cache_resource
def spending_history() -> pd.DataFrame:
    # fake spending history: log-normal amounts (lots of small purchases, a few big
    # ones), fixed seed so results are repeatable
    rng = np.random.default_rng(42)
    online = rng.random(HISTORY_SIZE) < 0.4
    amount = np.where(
        online,
        rng.lognormal(np.log(60), 0.6, HISTORY_SIZE),  # online: median ~$60
        rng.lognormal(np.log(30), 0.5, HISTORY_SIZE),
    )  # in store: median ~$30
    hour = np.where(online, rng.normal(17, 3.5, HISTORY_SIZE), rng.normal(14, 3.0, HISTORY_SIZE))
    return pd.DataFrame(
        {
            "Amount": amount.round(2),
            "Hour": np.clip(np.round(hour), 7, 23).astype(int),  # awake hours only
            "Type": np.where(online, "Online", "In-Store"),
        }
    )


def model_features(df: pd.DataFrame) -> np.ndarray:
    # log amount (so $20 vs $40 counts like $200 vs $400), hour, online as 0/1
    return np.column_stack(
        [
            np.log1p(df["Amount"].to_numpy(dtype=float)),
            df["Hour"].to_numpy(dtype=float),
            (df["Type"] == "Online").to_numpy(dtype=float),
        ]
    )


@st.cache_resource
def anomaly_model():
    # LOF flags purchases sitting in a sparse region compared with their neighbours.
    # Tried IsolationForest first but it missed 3 AM purchases - there's no night-time
    # data in the history and tree splits only cover the range seen in training.
    if not SKLEARN_OK:
        return None
    model = make_pipeline(
        StandardScaler(),
        LocalOutlierFactor(
            n_neighbors=MODEL_NEIGHBOURS, novelty=True, contamination=MODEL_CONTAMINATION
        ),
    )
    model.fit(model_features(spending_history()))
    return model


def robust_z(values: np.ndarray, baseline: np.ndarray) -> np.ndarray:
    # median/MAD instead of mean/std so a few big past purchases don't skew the baseline
    median = np.median(baseline)
    mad = np.median(np.abs(baseline - median))
    return 0.6745 * (values - median) / mad


def detect_fraud(ledger: list[dict]) -> pd.DataFrame:
    # one row per finding; Key stays stable across reruns so each alert fires once
    columns = ["Key", "Time", "Severity", "Alert", "Details"]
    if not ledger:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(ledger)
    df["Txn"] = range(len(df))  # position in the log = stable id
    df["Time"] = pd.to_datetime(df["Timestamp"])
    df["Approved"] = df["Status"].str.endswith("APPROVED")
    alerts = []

    # 1. bursts - rolling count of blocked attempts per channel
    blocks = df[df["Security block"]]
    for _, group in blocks.groupby("Type"):
        rolling_count = group.set_index("Time")["Txn"].rolling(BURST_WINDOW).count()
        group = group.assign(Blocks=rolling_count.to_numpy())
        # alert on the attempt that crosses the threshold
        for row in group[group["Blocks"] == BURST_THRESHOLD].itertuples():
            alerts.append(
                {
                    "Key": f"burst-{row.Txn}",
                    "Time": row.Time,
                    "Severity": "High",
                    "Alert": f"{BURST_THRESHOLD} blocked {row.Type.lower()} attempts in {BURST_WINDOW}",
                    "Details": "Repeated failures in a short time suggest someone is testing or "
                    "guessing your card details.",
                }
            )

    # 2. expired CVV = old card data being reused
    leaked = df[df["Reason"].str.contains("CVV expired", na=False)]
    for row in leaked.itertuples():
        alerts.append(
            {
                "Key": f"leaked-{row.Txn}",
                "Time": row.Time,
                "Severity": "High",
                "Alert": f"Stolen card data used online (${row.Amount:,.2f})",
                "Details": "Someone entered an old CVV, which usually means your card details "
                "were leaked. Consider replacing the card.",
            }
        )

    # 3. cardholder denied the push
    rejected = df[df["Reason"].str.contains("denied the push", na=False)]
    for row in rejected.itertuples():
        alerts.append(
            {
                "Key": f"rejected-{row.Txn}",
                "Time": row.Time,
                "Severity": "High",
                "Alert": f"Online purchase rejected at confirmation (${row.Amount:,.2f})",
                "Details": "Someone had a valid CVV but could not confirm the purchase. "
                "Your current CVV may have been phished.",
            }
        )

    # 4 and 5 only look at approved purchases
    approved = df[df["Approved"]].copy()
    if not approved.empty:
        history = spending_history()

        # 4. amount outliers vs history for the same channel
        approved["Z"] = 0.0
        for channel, idx in approved.groupby("Type").groups.items():
            baseline = np.log1p(history.loc[history["Type"] == channel, "Amount"].to_numpy())
            approved.loc[idx, "Z"] = robust_z(
                np.log1p(approved.loc[idx, "Amount"].to_numpy()), baseline
            )
        typical = history.groupby("Type")["Amount"].median()
        for row in approved[approved["Z"] > ROBUST_Z_LIMIT].itertuples():
            alerts.append(
                {
                    "Key": f"outlier-{row.Txn}",
                    "Time": row.Time,
                    "Severity": "Medium",
                    "Alert": f"Unusually large {row.Type.lower()} purchase (${row.Amount:,.2f})",
                    "Details": f"Robust z-score {row.Z:.1f} (limit {ROBUST_Z_LIMIT}); your typical "
                    f"{row.Type.lower()} purchase is about ${typical[row.Type]:,.0f}.",
                }
            )

        # 5. LOF on amount + hour + channel (catches e.g. a normal purchase at 3 AM)
        model = anomaly_model()
        if model is not None:
            approved["Flag"] = model.predict(model_features(approved))  # -1 = anomaly
            approved["Score"] = model.score_samples(model_features(approved))
            already = set(approved.loc[approved["Z"] > ROBUST_Z_LIMIT, "Txn"])
            for row in approved[
                (approved["Flag"] == -1) & ~approved["Txn"].isin(already)
            ].itertuples():
                alerts.append(
                    {
                        "Key": f"model-{row.Txn}",
                        "Time": row.Time,
                        "Severity": "Medium",
                        "Alert": f"Unusual {row.Type.lower()} purchase pattern (${row.Amount:,.2f} at {row.Hour}:00)",
                        "Details": f"The ML model rates this amount, time and channel as unlike your "
                        f"history (anomaly score {row.Score:.2f}). Check that it was you.",
                    }
                )

    if not alerts:
        return pd.DataFrame(columns=columns)
    out = pd.DataFrame(alerts, columns=columns)
    out["Rank"] = out["Severity"].map(SEVERITY_ORDER)
    return out.sort_values(["Time", "Rank"], ascending=[False, True]).drop(columns="Rank")


def send_mac_notification(title: str, message: str) -> None:
    if not mac_push_available():
        return
    script = (
        f'display notification "{_applescript_text(message)}" '
        f'with title "{_applescript_text(title)}" sound name "Basso"'
    )
    with contextlib.suppress(OSError):
        subprocess.Popen(
            ["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )


def run_fraud_monitor() -> pd.DataFrame:
    ss = st.session_state
    alerts = detect_fraud(ss.ledger)
    new = alerts[~alerts["Key"].isin(ss.alerted_keys)]
    for row in new.itertuples():
        ss.alerted_keys.add(row.Key)
        st.toast(row.Alert, icon="🚨")
        if ss.fraud_notify:
            send_mac_notification(f"{ISSUER} fraud alert", f"{row.Alert}. {row.Details}")
    return alerts


CHART_STYLES = {
    # different shapes too, so it isn't colour-only
    "Approved": {"color": "#3FBF7F", "symbol": "circle"},
    "Declined": {"color": "#E5534B", "symbol": "x"},
    "Flagged": {"color": "#E9B949", "symbol": "diamond"},
}


def spending_chart(alerts: pd.DataFrame) -> None:
    if go is None:
        return
    history = spending_history()
    st.caption(
        "Grey dots are your past purchases, which the fraud models treat as normal. "
        "A purchase far from the grey cloud gets flagged. Hover over any dot for details."
    )
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=history["Hour"],
            y=history["Amount"],
            mode="markers",
            name="Your history",
            marker={"color": "rgba(141,154,176,0.32)", "size": 6},
            customdata=history["Type"],
            hovertemplate="History, %{customdata}<br>$%{y:,.2f} at %{x}:00<extra></extra>",
        )
    )
    if st.session_state.ledger:
        df = pd.DataFrame(st.session_state.ledger)
        df = df[df["Amount"] > 0].copy()
        flagged_txns = {
            int(key.split("-")[1])
            for key in alerts["Key"]
            if key.startswith(("outlier-", "model-"))
        }
        df["Txn"] = df.index
        df["Group"] = np.where(
            df["Txn"].isin(flagged_txns),
            "Flagged",
            np.where(df["Status"].str.endswith("APPROVED"), "Approved", "Declined"),
        )
        for group, style in CHART_STYLES.items():
            part = df[df["Group"] == group]
            if part.empty:
                continue
            fig.add_trace(
                go.Scatter(
                    x=part["Hour"],
                    y=part["Amount"],
                    mode="markers",
                    name=group,
                    marker={
                        "color": style["color"],
                        "symbol": style["symbol"],
                        "size": 13,
                        "line": {"width": 2, "color": "#0D1522"},
                    },
                    customdata=np.column_stack([part["Type"], part["Reason"]]),
                    hovertemplate=(
                        f"<b>{group}</b>, %{{customdata[0]}}<br>$%{{y:,.2f}} at %{{x}}:00"
                        "<br>%{customdata[1]}<extra></extra>"
                    ),
                )
            )
    fig.update_layout(
        height=400,
        margin={"l": 70, "r": 16, "t": 36, "b": 56},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "IBM Plex Sans, sans-serif", "color": "#8D9AB0"},
        legend={"orientation": "h", "y": 1.08, "x": 0},
        xaxis={
            "title": "Hour of day",
            "range": [-0.5, 23.5],
            "dtick": 3,
            "showgrid": False,
            "zeroline": False,
            "linecolor": "#26344D",
        },
        yaxis={
            "title": "Amount (CAD, log scale)",
            "type": "log",
            "gridcolor": "rgba(141,154,176,0.12)",
            "zeroline": False,
            "tickvals": [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
            "ticktext": ["$5", "$10", "$25", "$50", "$100", "$250", "$500", "$1k", "$2.5k", "$5k"],
            "minor": {"showgrid": False},
        },
        hoverlabel={"bgcolor": "#131E30", "bordercolor": "#26344D", "font": {"color": "#E4E8EF"}},
    )
    st.plotly_chart(fig, theme=None)


def alerts_html(alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return (
            '<div class="nv-empty">No suspicious patterns yet. Try tapping the card three times '
            "without a fingerprint, or paying with leaked card data.</div>"
        )
    rows = []
    for row in alerts.itertuples():
        rows.append(
            f'<div class="nv-alert"><span class="nv-sev {row.Severity}"><i></i>{row.Severity}</span>'
            f"<div><b>{row.Alert}</b><p>{row.Details}</p></div>"
            f"<time>{row.Time:%H:%M:%S}</time></div>"
        )
    return "".join(rows)


def bank_dashboard() -> None:
    ss = st.session_state
    alerts = run_fraud_monitor()
    ledger = ss.ledger

    total = len(ledger)
    approved = [e for e in ledger if e["Status"].endswith("APPROVED")]
    blocked = sum(1 for e in ledger if e["Security block"])
    rate = f"{len(approved) / total:.0%}" if total else "No payments yet"
    html(f"""
<div class="nv-bank-head"><div><div class="nv-title">Bank server</div>
  <p>Every payment attempt lands here. The bank approves or declines it, then looks across the whole log for fraud patterns.</p></div></div>
<div class="nv-stats">
  <div class="nv-stat"><b>{total}</b><span>Payment attempts</span></div>
  <div class="nv-stat"><b>{len(approved)}</b><span>Approved ({rate})</span></div>
  <div class="nv-stat"><b>{blocked}</b><span>Fraud attempts blocked</span></div>
  <div class="nv-stat {'alert' if len(alerts) else ''}"><b>{len(alerts)}</b><span>Fraud alerts</span></div>
  <div class="nv-stat"><b>${sum(e['Amount'] for e in approved):,.2f}</b><span>Approved volume</span></div>
</div>
""")

    missing = [
        name for name, ok in (("scikit-learn", SKLEARN_OK), ("plotly", go is not None)) if not ok
    ]
    if missing:
        st.info(
            f"Install {' and '.join(missing)} to turn on the ML model and spending chart: "
            f"`pip3 install {' '.join(missing)}`"
        )

    tab_alerts, tab_chart, tab_log, tab_how = st.tabs(
        [
            f"Fraud alerts ({len(alerts)})",
            "Spending profile",
            f"Transaction log ({total})",
            "How it works",
        ]
    )

    with tab_alerts:
        html(alerts_html(alerts))

    with tab_chart:
        spending_chart(alerts)

    with tab_log:
        if ledger:
            df = pd.DataFrame(ledger).iloc[::-1]
            st.dataframe(df, hide_index=True)
            d1, d2, _ = st.columns([1, 1, 3])
            d1.download_button(
                "Download CSV",
                df.to_csv(index=False),
                "audit_log.csv",
                "text/csv",
                icon=":material/download:",
            )
            if d2.button("Clear log", icon=":material/delete:"):
                ss.ledger = []
                ss.alerted_keys = set()
                ss.pos_result = None
                ss.online_result = None
                st.rerun()
        else:
            html(
                '<div class="nv-empty">No payments yet. Tap the card at Corner Market or check out at '
                f"{MERCHANT_NAME} to start the log.</div>"
            )
        with st.expander("Bank internals (a real bank never shows these)"):
            bank_totp = pyotp.TOTP(ss.bank_secret, digits=CVV_DIGITS, interval=CVV_STEP_SECONDS)
            now = time.time()
            st.write(
                {
                    "current_time_step": int(now // CVV_STEP_SECONDS),
                    "expected_cvv_now": bank_totp.now(),
                    "previous_window_cvv": bank_totp.at(now - CVV_STEP_SECONDS),
                    "consecutive_bad_cvvs": ss.cvv_failures,
                    "online_blocked": time.monotonic() < ss.online_blocked_until,
                }
            )

    with tab_how:
        explainer()


def explainer() -> None:
    st.markdown(f"""
**Match-on-Card.** The fingerprint template is stored and compared inside the card's secure
element. The print never leaves the card, so there is no biometric database to breach. A match
only unlocks the payment chip for {UNLOCK_WINDOW_SECONDS} seconds; a stolen card is useless at a
terminal.

**Dynamic CVV (TOTP, RFC 6238).** Card and bank share a secret set at personalization. Each
computes `HMAC-SHA1(secret, floor(time / {CVV_STEP_SECONDS}))`, truncated to {CVV_DIGITS}
digits. Card data stolen in a breach carries a CVV that expires within {CVV_STEP_SECONDS // 60}
minutes.

**Timeout handling.** Windows are enforced by comparing a monotonic clock at the moment of
payment, not by the on-screen countdown, and the card fails closed (locked) by default.

**Push approval (step-up authentication).** A dynamic CVV defeats stolen data, but not a
phishing page that tricks you into typing the *current* CVV and replays it within minutes. So
after the CVV passes, the bank asks you on a separate device to approve this exact merchant and
amount, and on a Mac with Touch ID the approval also needs your fingerprint. The attacker has
the code, not your device.

**Fraud monitor (pandas).** Single rules catch single bad attempts; the monitor looks for
patterns across the whole log: {BURST_THRESHOLD}+ blocked attempts in one channel within
{BURST_WINDOW} (time-based rolling window per channel), stolen card data replayed online, and
purchases rejected at confirmation. Each new finding alerts the cardholder once.

**Spending anomalies (NumPy + scikit-learn).** The bank learns your normal spending from past
transactions. NumPy flags amounts with a robust z-score above {ROBUST_Z_LIMIT} (median and MAD,
so a few big past purchases cannot hide new fraud). A Local Outlier Factor model looks at
amount, time and channel together and flags purchases that land in an "empty" region of your
history, like a normal-sized purchase at 3 AM. It is unsupervised: it needs no examples of
fraud, only of normal behaviour. Plotly charts your purchases against that normal profile.

**Why limits matter.** {CVV_DIGITS} digits is only 1,000 values, so the bank blocks online
payments after {MAX_CVV_FAILURES} wrong CVVs and refuses to accept the same code twice (replay
protection).
""")


# --- Page ---
def main() -> None:
    st.set_page_config(page_title="Nova card security lab", page_icon="💳", layout="wide")
    init_state()
    st.markdown(f"<style>{STYLE_PATH.read_text()}</style>", unsafe_allow_html=True)

    with st.sidebar:
        security_settings()

    card_panel()

    left, right = st.columns(2, gap="large")
    with left:
        pos_terminal()
    with right:
        online_checkout()

    bank_dashboard()


main()
