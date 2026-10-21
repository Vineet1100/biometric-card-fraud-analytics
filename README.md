# Biometric card & fraud analytics

A Streamlit app that simulates a payment card that only works for its owner, plus the bank-side fraud detection behind it.

I wanted to see how a few ideas from card security fit together in one place: biometric cards, dynamic CVVs, step-up authentication and transaction monitoring. So I built all three parties (card, merchants, bank) into a single app you can click through.

## What it does

**In store.** The card's chip stays locked until a fingerprint matches, then unlocks for 15 seconds. Tapping outside that window gets declined. On a Mac it uses the real Touch ID sensor; anywhere else the scan is simulated.

**Online.** The CVV on the card's e-ink screen is a TOTP code (RFC 6238) that changes every 2 minutes. The card and bank share a secret and each compute the code from the current time, so stolen card details stop working once the window moves on. If the CVV is valid, the bank still asks the cardholder to approve the purchase (a macOS alert, confirmed with Touch ID). The bank also refuses reused codes and blocks online payments after 3 wrong CVVs.

**Fraud monitoring.** Every attempt goes into a log, and after each one the bank looks for patterns:

- 3+ blocked attempts in the same channel within 5 minutes (pandas `groupby` + time-based `rolling`)
- an expired CVV being used, which suggests leaked card data
- a purchase the cardholder denied
- amounts far outside normal spending, using a robust z-score (median/MAD with NumPy)
- unusual combinations of amount, time of day and channel, using a scikit-learn Local Outlier Factor model trained on spending history

New alerts show up in the app and as a macOS notification. There's also a Plotly chart of each purchase against the spending history.

On the model: I started with Isolation Forest, but on five out-of-pattern test purchases it caught 2 and LOF caught all 5. The history has no night-time purchases, and tree splits only cover the range seen in training, so the forest couldn't tell that 3 AM was unusual.

## Running it

Needs Python 3.10+.

```bash
git clone https://github.com/Vineet1100/biometric-card-fraud-analytics.git
cd biometric-card-fraud-analytics
pip install -r requirements.txt
streamlit run app.py
```

Then open http://localhost:8501 in your browser (Streamlit usually opens it for you).

Some things to try:

- tap the card without scanning, then scan and tap again
- pay online with "Use my card" and approve the request
- pay with "Use leaked data" to trigger the stolen-data alert
- tap the locked card three times in a row
- set "Purchase time" to 3 AM in the sidebar and make a normal purchase

## Limitations

It's a simulation, so a few things are simplified:

- the CVV secret is kept in app memory; on a real card it lives in the secure element and the bank's HSM
- the spending history is generated with NumPy, not real transaction data
- real in-store payments are authorized with EMV cryptograms, not by checking whether the card is unlocked
- decline reasons are detailed on purpose; a real merchant only gets generic codes

## License

MIT
