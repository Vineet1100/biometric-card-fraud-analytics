"""Words shown on the pages: mission briefings and the How it works page."""

MISSIONS = {
    1: dict(route="store", name="Pay in store", title="Tap the card at a store",
            lead="First tap without scanning: it gets declined. Then hold the sensor, and tap again before the ring runs out.",
            card="A stolen card is useless at a terminal. Unlock the chip with a fingerprint and tap."),
    2: dict(route="online", name="Pay online", title="Buy something online",
            lead="Read the code off the card, pay, then approve the purchase with your fingerprint. "
                 "The code changes every 2 minutes, so an old one fails.",
            card="The CVV changes every 2 minutes, and the owner approves each purchase."),
    3: dict(route="attack", name="Attack the card", title="Try to break in",
            lead="These are three ways criminals attack cards. Run each one and watch the bank block it and raise an alert.",
            card="Replay leaked data, test a stolen card, guess the CVV. See every attack blocked."),
    4: dict(route="fraud-ai", name="Fraud AI", title="Ask the fraud AI",
            lead="The grey dots are the owner's last 400 purchases. Set up a new purchase and the model decides "
                 "whether it looks like them.",
            card="Test purchases against a model that learned the owner's spending."),
}

BRIEF = {
    1: dict(title="Fingerprint unlock",
            body="The card is switched off until its owner's fingerprint matches. The match happens on the card itself, "
                 "so the fingerprint is never sent to the store or the bank. A stolen card can't be tapped.",
            how=["Match-on-card biometrics: your real Touch ID on a Mac (through passkeys), simulated elsewhere",
                 "15-second unlock window, checked by the server's clock, not the page",
                 "3 wrong fingers lock the sensor for 30 seconds"],
            tech=["Python", "Flask", "macOS Touch ID"]),
    2: dict(title="Live code + approval",
            body="The 3-digit code on the back changes every 2 minutes. The bank works out the same code on its own, so a "
                 "copied code goes stale fast. Then the owner approves the exact purchase with their fingerprint.",
            how=["TOTP codes (RFC 6238, HMAC-SHA1) with pyotp, the same maths as two-factor apps",
                 "Each code works once (replay protection)",
                 "Approval request lands as a notification on your laptop, and you approve with Touch ID"],
            tech=["pyotp", "HMAC", "Step-up auth"]),
    3: dict(title="Attack simulator",
            body="Run the attacks a criminal would try. Every one is declined by the Python bank, logged, and turned into "
                 "an alert for the bank's fraud team.",
            how=["Expired codes are recognised as leaked data",
                 "3 blocked attempts in 5 minutes triggers a card-testing alert",
                 "3 wrong codes pause online payments for a minute"],
            tech=["Python", "rolling windows", "fraud rules"]),
    4: dict(title="Fraud AI",
            body="The bank learns how the owner normally spends from 400 past purchases. Then it flags anything that doesn't "
                 "fit: a huge amount, or a normal amount at 3 AM when they never shop at night.",
            how=["Amount check: robust z-score using the median, so a few big purchases don't skew it",
                 "Pattern check: scikit-learn Local Outlier Factor on amount, time and channel",
                 "Caught 5 of 5 unusual test purchases, against 2 of 5 for Isolation Forest"],
            tech=["NumPy", "scikit-learn", "Flask API"]),
}

FLOW = [
    ("Unlock", "The fingerprint is matched on the card. Only a yes or no leaves the sensor, and the chip stays live for 15 seconds."),
    ("Live code", "Online, the bank works out the same 3-digit code from a shared secret and the time, so a copied code expires."),
    ("Approve", "The bank asks the owner to approve that exact amount and shop, with their fingerprint."),
    ("Watch", "Every attempt is logged, and the fraud monitor looks across the log for patterns a single decline can't show."),
]
