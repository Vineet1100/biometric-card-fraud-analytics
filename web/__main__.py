"""Run the card lab locally: python -m web"""
import os

from . import create_app

port = int(os.environ.get("PORT", 5000))
print(f"Biometric card lab running at http://127.0.0.1:{port}")
create_app().run(host="127.0.0.1", port=port, debug=False)
