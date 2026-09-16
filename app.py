"""
Email Exposure Scanner
=======================
A Have-I-Been-Pwned-style breach lookup tool.

Privacy design:
- Emails are NEVER stored, logged, or written to disk anywhere in this app.
- Lookups against the local simulated dataset are done by SHA-256 hash of the
  normalized (lowercased, trimmed) email, so the dataset itself never needs
  to contain plaintext emails.
- No passwords are ever requested, accepted, or processed. This tool only
  checks whether an email address appears in breach metadata (which
  breach, when, what data types were exposed) -- never credentials.
- Basic in-memory rate limiting is applied per IP to discourage bulk
  harvesting/enumeration of other people's addresses.
- Real HIBP integration (optional) is called over HTTPS with an API key
  supplied by the operator, and the response is relayed to the user without
  being cached or written to disk.

Two lookup modes:
1. SIMULATED (default) - looks up the email against data/simulated_breaches.json,
   a small local fixture, entirely offline. Good for demos/dev/testing.
2. LIVE HIBP - if the environment variable HIBP_API_KEY is set, real lookups
   are made against the Have I Been Pwned API (https://haveibeenpwned.com/API/v3).
   This requires a paid HIBP API key that YOU must obtain and are authorized
   to use; this code does not embed or fabricate one.

Run:
    pip install flask requests
    export HIBP_API_KEY=xxxx   # optional, omit to use simulated mode
    python app.py
Then open http://localhost:5000
"""

import hashlib
import json
import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
SIMULATED_DB_PATH = BASE_DIR / "data" / "simulated_breaches.json"

HIBP_API_KEY = os.environ.get("HIBP_API_KEY")  # None => simulated mode
HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------------------------------------------------------------------
# Rate limiting (in-memory, per-process). For production, replace with
# Redis/Flask-Limiter backed by a shared store.
# ---------------------------------------------------------------------------
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 5
_request_log = defaultdict(deque)


def is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    log = _request_log[client_ip]
    while log and now - log[0] > RATE_LIMIT_WINDOW_SECONDS:
        log.popleft()
    if len(log) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    log.append(now)
    return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_email(email: str) -> str:
    """SHA-256 of the normalized email. Used as the dataset lookup key so
    plaintext emails never need to be persisted in the simulated dataset."""
    return hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()


def load_simulated_db() -> dict:
    with open(SIMULATED_DB_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.pop("_comment", None)
    return data


def lookup_simulated(email: str) -> list:
    db = load_simulated_db()
    return db.get(hash_email(email), [])


def lookup_live_hibp(email: str) -> list:
    """Calls the real HIBP v3 API. Requires HIBP_API_KEY to be set.
    Returns a normalized list of breach dicts, same shape as the simulated
    dataset, so the frontend doesn't need to know which mode served it."""
    import requests  # local import so simulated mode has no hard dependency

    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "Email-Exposure-Scanner/1.0",
    }
    url = HIBP_API_URL.format(email=normalize_email(email))
    resp = requests.get(url, headers=headers, params={"truncateResponse": "false"}, timeout=10)

    if resp.status_code == 404:
        return []  # no breaches found
    if resp.status_code == 429:
        raise RuntimeError("Upstream rate limit hit, please try again shortly.")
    resp.raise_for_status()

    breaches = resp.json()
    normalized = []
    for b in breaches:
        normalized.append({
            "name": b.get("Title") or b.get("Name"),
            "date": b.get("BreachDate"),
            "compromised_data": b.get("DataClasses", []),
            "severity": "high" if "Passwords" in b.get("DataClasses", []) else "medium",
        })
    return normalized


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", mode="live" if HIBP_API_KEY else "simulated")


@app.route("/api/check", methods=["POST"])
def check_email():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if is_rate_limited(client_ip):
        return jsonify({
            "error": "Too many requests. Please wait a minute before trying again."
        }), 429

    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "")

    if not email or not EMAIL_RE.match(email):
        return jsonify({"error": "Please provide a valid email address."}), 400

    # Never log the raw email. If logging is added, log only the hash.
    try:
        if HIBP_API_KEY:
            breaches = lookup_live_hibp(email)
            source = "live"
        else:
            breaches = lookup_simulated(email)
            source = "simulated"
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Lookup failed: {exc}"}), 502

    return jsonify({
        "source": source,
        "breach_count": len(breaches),
        "breaches": breaches,
        "note": (
            "SIMULATED demo data - not a real breach lookup."
            if source == "simulated"
            else "Data from Have I Been Pwned."
        ),
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "mode": "live" if HIBP_API_KEY else "simulated"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
