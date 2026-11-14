"""The Flask card lab: pages, the JSON API, and the card and bank rules behind it."""
import pytest

from web import create_app
from web.lab import CardLab, SessionStore


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture()
def client():
    app = create_app({"TESTING": True, "SECRET_KEY": "test"})
    return app.test_client()


@pytest.fixture()
def lab():
    return CardLab(clock=Clock())


# ------------------------------------------------------------------ pages
@pytest.mark.parametrize("path", ["/", "/mission/store", "/mission/online", "/mission/attack", "/mission/fraud-ai", "/bank", "/how"])
def test_every_page_renders(client, path):
    r = client.get(path)
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "BIOMETRIC CARD LAB" in html and 'aria-current="page"' in html
    assert "lab.js" in html and "lab.css" in html


def test_short_links_redirect(client):
    r = client.get("/fraud-ai")
    assert r.status_code == 302 and r.headers["Location"].endswith("/mission/fraud-ai")


def test_unknown_pages(client):
    assert client.get("/mission/nope").status_code == 404
    assert client.get("/nothing").status_code == 404
    assert client.get("/api/nothing").get_json() == {"error": "not found"}


def test_static_files_and_health(client):
    assert client.get("/static/lab.js").status_code == 200
    assert client.get("/static/lab.css").status_code == 200
    assert client.get("/healthz").get_json() == {"ok": True}


def test_security_headers_and_cookie(client):
    r = client.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_api_only_accepts_json(client):
    assert client.post("/api/tap", data={"amount": "5"}).status_code == 415


@pytest.mark.parametrize("body", [{"amount": -1, "hour": 12}, {"amount": "x", "hour": 12}, {"amount": 5, "hour": 24}])
def test_bad_input_is_rejected(client, body):
    assert client.post("/api/tap", json=body).status_code == 400


# ------------------------------------------------------------------ a whole visit through the API
def test_full_visit_through_the_api(client):
    st = client.get("/api/state").get_json()
    assert len(st["cvv"]) == 3 and st["stats"]["attempts"] == 0

    # mission 01: locked tap, scan, tap
    assert client.post("/api/tap", json={"amount": 42.5, "hour": 12}).get_json()["entry"]["ok"] is False
    assert client.post("/api/scan", json={"finger": "owner"}).get_json()["result"]["result"] == "match"
    r = client.post("/api/tap", json={"amount": 42.5, "hour": 12}).get_json()
    assert r["entry"]["ok"] is True and 1 in r["state"]["done"]

    # mission 02: pay with the card's current code, then approve
    cvv = client.get("/api/state").get_json()["cvv"]
    r = client.post("/api/pay", json={"pan": "4111 1111 1111 1111", "cvv": cvv, "amount": 249.99, "hour": 12}).get_json()
    assert r["status"] == "pending" and r["state"]["pending"]["amount"] == 249.99
    r = client.post("/api/approve", json={"decision": "approve"}).get_json()
    assert r["entry"]["ok"] is True and 2 in r["state"]["done"]
    # the same code can't be used twice
    r = client.post("/api/pay", json={"pan": "4111111111111111", "cvv": cvv, "amount": 10, "hour": 12}).get_json()
    assert r["status"] == "declined" and "already used" in r["entry"]["reason"]

    # mission 03: attacks raise alerts
    r = client.post("/api/attack/replay", json={"hour": 12}).get_json()
    assert r["status"] == "declined" and r["stale"] is True
    r = client.post("/api/attack/testing", json={"hour": 12}).get_json()
    assert [e["ok"] for e in r["entries"]] == [False, False, False]
    titles = [a["title"] for a in r["state"]["alerts"]]
    assert any("Stolen card data" in t for t in titles) and any("3 blocked in-store" in t for t in titles)

    # mission 04: the 3 AM lunch is caught by the model
    j = client.post("/api/judge", json={"amount": 42.5, "at_hour": 3, "online": False, "preset": True}).get_json()
    assert j["flagged"] and j["pattern"] and not j["outlier"] and 4 in j["done"]

    # the pages show what happened
    assert "4 of 4 missions complete" in client.get("/").get_data(as_text=True)
    bank = client.get("/bank").get_data(as_text=True)
    assert "CVV expired" in bank and "Stolen card data used online" in bank


def test_each_browser_gets_its_own_lab():
    app = create_app({"TESTING": True, "SECRET_KEY": "test"})
    a, b = app.test_client(), app.test_client()
    a.post("/api/tap", json={"amount": 5, "hour": 12})
    assert a.get("/api/state").get_json()["stats"]["attempts"] == 1
    assert b.get("/api/state").get_json()["stats"]["attempts"] == 0


def test_history_endpoint(client):
    h = client.get("/api/history").get_json()
    assert len(h) == 400 and {"amount", "hour", "online"} <= set(h[0])


# ------------------------------------------------------------------ the rules, with a controllable clock
def test_unlock_window_expires(lab):
    lab.scan(True)
    lab.clock.t += 14
    assert lab.tap(10, 12).ok
    lab.clock.t += 2
    assert not lab.tap(10, 12).ok


def test_three_wrong_fingers_lock_the_sensor(lab):
    assert [lab.scan(False)["result"] for _ in range(3)] == ["fail", "fail", "lockout"]
    assert lab.scan(True)["result"] == "locked"
    lab.clock.t += 31
    assert lab.scan(True)["result"] == "match"


def test_code_changes_every_two_minutes_and_old_code_is_leaked_data(lab):
    old = lab.cvv_now()
    lab.clock.t += 240
    res = lab.pay_online("4111111111111111", old, 50, 12)
    if old == lab.cvv_now():          # 1 in 1000 chance the new code matches the old one
        pytest.skip("codes collided")
    assert res["status"] == "declined" and res["stale"]


def test_three_wrong_codes_pause_online_payments(lab):
    wrong = f"{(int(lab.cvv_now()) + 1) % 1000:03d}"
    for _ in range(3):
        lab.pay_online("4111111111111111", wrong, 5, 12)
    res = lab.pay_online("4111111111111111", lab.cvv_now(), 5, 12)
    assert res["status"] == "declined" and "paused" in res["message"]
    lab.clock.t += 61
    lab.used_steps.clear()
    assert lab.pay_online("4111111111111111", lab.cvv_now(), 5, 12)["status"] == "pending"


def test_unanswered_approval_times_out(lab):
    lab.pay_online("4111111111111111", lab.cvv_now(), 80, 12)
    lab.clock.t += 61
    st = lab.state()
    assert st["pending"] is None and st["ledger"][0]["reason"] == "No answer to approval request"


def test_denied_purchase_alerts(lab):
    lab.pay_online("4111111111111111", lab.cvv_now(), 80, 12)
    lab.decide("deny")
    assert lab.alerts[0].title.startswith("Purchase rejected by the owner")


def test_large_approved_purchase_is_flagged(lab):
    lab.pay_online("4111111111111111", lab.cvv_now(), 1500, 14)
    lab.decide("approve")
    assert lab.alerts and lab.alerts[0].sev == "med" and "Unusually large" in lab.alerts[0].title


def test_session_store_evicts_least_recent():
    store = SessionStore(max_sessions=3)
    ids = [store.get(None)[0] for _ in range(3)]
    store.get(ids[0])                 # touch the first so it is the most recent
    store.get(None)
    assert len(store) == 3
    assert store.get(ids[0])[0] == ids[0]
    assert store.get(ids[1])[0] != ids[1]      # the oldest unused one was dropped
