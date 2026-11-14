"""Fraud scoring: robust z-score on the amount, Local Outlier Factor on the pattern.

Same methods as app.py, without the Streamlit parts.
"""

from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROBUST_Z_LIMIT = 3.5
HISTORY_SIZE = 400


@dataclass(frozen=True)
class Score:
    robust_z: float
    lof_flagged: bool
    flagged: bool
    reason: str


@lru_cache(maxsize=1)
def _history() -> dict[str, np.ndarray]:
    # simulated spending history: log-normal amounts, fixed seed so results repeat
    rng = np.random.default_rng(42)
    online = rng.random(HISTORY_SIZE) < 0.4
    amount = np.where(
        online,
        rng.lognormal(np.log(60), 0.6, HISTORY_SIZE),
        rng.lognormal(np.log(30), 0.5, HISTORY_SIZE),
    )
    hour = np.where(online, rng.normal(17, 3.5, HISTORY_SIZE), rng.normal(14, 3.0, HISTORY_SIZE))
    return {"amount": amount, "hour": np.clip(np.round(hour), 7, 23), "online": online}


def _features(amount: np.ndarray, hour: np.ndarray, online: np.ndarray) -> np.ndarray:
    return np.column_stack([np.log1p(amount), hour, online.astype(float)])


@lru_cache(maxsize=1)
def _model():
    h = _history()
    model = make_pipeline(
        StandardScaler(),
        LocalOutlierFactor(n_neighbors=35, novelty=True, contamination=0.01),
    )
    return model.fit(_features(h["amount"], h["hour"], h["online"]))


def _robust_z(amount: float, online: bool) -> float:
    h = _history()
    baseline = np.log1p(h["amount"][h["online"] == online])
    median = np.median(baseline)
    mad = np.median(np.abs(baseline - median))
    return float(0.6745 * (np.log1p(amount) - median) / mad)


def score(amount: float, hour: int, online: bool) -> Score:
    z = _robust_z(amount, online)
    features = _features(np.array([amount]), np.array([hour]), np.array([online]))
    lof_flagged = bool(_model().predict(features)[0] == -1)
    if z > ROBUST_Z_LIMIT:
        reason = "amount far outside normal spending"
    elif lof_flagged:
        reason = "amount, time and channel unlike the cardholder's history"
    else:
        reason = "fits normal spending"
    return Score(round(z, 2), lof_flagged, z > ROBUST_Z_LIMIT or lof_flagged, reason)


def lof_details(amount: float, hour: int, online: bool) -> tuple[float, float]:
    """The Local Outlier Factor for one purchase and the score above which it is flagged."""
    model = _model()
    features = _features(np.array([amount]), np.array([hour]), np.array([online]))
    lof = float(-model.score_samples(features)[0])
    return lof, float(-model[-1].offset_)


def history() -> list[dict]:
    """The simulated past purchases the model learned from, for charting."""
    h = _history()
    return [
        {"amount": round(float(a), 2), "hour": int(hr), "online": bool(o)}
        for a, hr, o in zip(h["amount"], h["hour"], h["online"], strict=True)
    ]
