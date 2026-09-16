

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
    
    import requests

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
