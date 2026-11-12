# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. Don't open a public issue for anything that could be exploited.

Include what you found, how to reproduce it and what an attacker could do with it. I'll reply within a week.

## Scope

This is a prototype for learning and demonstration. It processes no real card data, and it should never be used with real card numbers or real money. See [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) for the threat model and the controls in place.

## Secrets

No keys or credentials belong in this repository. Generate your own with `python -m bank.keys > .env`. Every push is scanned for leaked secrets, and if a key is ever exposed, rotate it straight away.
