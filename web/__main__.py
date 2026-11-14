"""Run the card lab locally: python -m web"""
import os

from . import create_app

# 5000 is taken by AirPlay Receiver on macOS, which answers with a 403
port = int(os.environ.get("PORT", 8000))
print(f"Biometric card lab running at http://127.0.0.1:{port}")
create_app().run(host="127.0.0.1", port=port, debug=False)
