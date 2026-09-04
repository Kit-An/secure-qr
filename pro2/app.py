"""
app.py
Flask backend for SecureQR web version.

Wraps the existing scanner.py (heuristics + Google Safe Browsing) and
generates a QR code in memory (no file saved, no image.show() popup -
this runs on a server, popping a window there would make no sense for
a web app).

Run:
    python app.py
Then open:
    http://127.0.0.1:5000

Optional: set an environment variable to enable real Google Safe
Browsing checks (otherwise the app still works using local heuristics
only):
    Windows (PowerShell):  $env:SAFE_BROWSING_API_KEY="your_key_here"
    Windows (cmd):         set SAFE_BROWSING_API_KEY=your_key_here
    macOS/Linux:           export SAFE_BROWSING_API_KEY="your_key_here"

Requires: pip install flask qrcode[pil]
(scanner.py/cache.py/canonicalizer.py have no extra dependencies beyond
the standard library)
"""

import base64
import io
import os
import re
import urllib.parse

import qrcode
from flask import Flask, jsonify, request, send_from_directory

from scanner import evaluate_heuristics, query_google_safe_browsing

app = Flask(__name__, static_folder="public", static_url_path="")

# Color the QR code itself based on risk, same idea as the desktop version.
RISK_COLORS = {"Low": "#1a7f37", "Medium": "#b8860b", "High": "#c62828"}


def normalize_url(raw_url: str) -> str:
    """Add https:// if the user forgot a scheme, same behavior as main.py's CLI."""
    raw_url = raw_url.strip()
    if raw_url and not urllib.parse.urlparse(raw_url).scheme:
        raw_url = "https://" + raw_url
    return raw_url


_DOMAIN_PATTERN = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|"  # domain.tld
    r"^(\d{1,3}\.){3}\d{1,3}$"  # or a raw IPv4 address
)


def is_valid_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    hostname = parsed.hostname or ""
    # A netloc with a space or missing a dot (e.g. "not a url!!") should fail here.
    return bool(_DOMAIN_PATTERN.match(hostname)) or hostname == "localhost"


def generate_qr_base64(data: str, risk_level: str) -> str:
    """Generate a QR code in memory and return it as a base64 PNG string."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    fill_color = RISK_COLORS.get(risk_level, "black")
    img = qr.make_image(fill_color=fill_color, back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/status")
def status():
    """Tells the frontend whether a default Safe Browsing key is configured
    on this machine, without ever revealing the key itself."""
    return jsonify({"default_key_available": bool(os.getenv("SAFE_BROWSING_API_KEY"))})


@app.route("/check", methods=["POST"])
def check():
    payload = request.get_json(silent=True) or {}
    raw_url = (payload.get("url") or "").strip()
    key_mode = payload.get("key_mode", "default")  # "default" or "own"
    own_api_key = (payload.get("api_key") or "").strip()

    if not raw_url:
        return jsonify({"valid": False, "error": "Please enter a URL."}), 400

    url = normalize_url(raw_url)

    if not is_valid_url(url):
        return jsonify({
            "valid": False,
            "url": url,
            "error": "That doesn't look like a valid URL.",
        })

    # 1. Local heuristics (always runs, no internet dependency)
    heuristics = evaluate_heuristics(url)
    score = heuristics["score"]
    warnings = heuristics["warnings"]

    # 2. Google Safe Browsing (only runs if a key is available for this request)
    if key_mode == "own":
        api_key = own_api_key or None
    else:
        # Default mode: use whatever is set in the environment on THIS machine.
        # The key itself is never stored in source code or sent to the browser.
        api_key = os.getenv("SAFE_BROWSING_API_KEY")

    safe_browsing = None
    if api_key:
        safe_browsing = query_google_safe_browsing(url, api_key)
    elif key_mode == "own" and not own_api_key:
        safe_browsing = {"checked": False, "error": "No API key entered."}

    flagged_by_api = bool(safe_browsing and safe_browsing.get("flagged"))

    # Decide overall risk level (same thresholds main.py uses: score >= 3 is hazardous)
    if flagged_by_api:
        risk_level = "High"
    elif score >= 3:
        risk_level = "High"
    elif score >= 1:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    qr_base64 = generate_qr_base64(url, risk_level)

    return jsonify({
        "valid": True,
        "url": url,
        "risk_level": risk_level,
        "score": score,
        "warnings": warnings,
        "safe_browsing": safe_browsing,
        "qr_base64": qr_base64,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
