"""Intentionally-vulnerable backend for the dvmobile lab.

The request logic is a pure function, :func:`handle`, so the test-suite (and the
challenge writeups) can drive it directly without binding a socket. :func:`serve`
wraps it in ``http.server`` for interactive lab use.

EVERY vulnerability here is deliberate and documented in ``challenges/``. Do not
copy these patterns into real software — that is the anti-pattern the lab
teaches you to recognize.
"""

from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from .challenges import BY_ID

# --- seed data (the "backend") ---------------------------------------------
USERS = {
    "1": {"id": "1", "name": "you", "email": "you@lab.local", "balance": 100},
    # VULN: user 2's profile holds the IDOR flag; no per-user access control.
    "2": {"id": "2", "name": "victim", "email": "victim@lab.local",
          "balance": 999999, "note": BY_ID["idor-profile"].flag},
}

# VULN: bootstrap config shipped to the mobile client embeds a secret.
APP_CONFIG = {
    "api_base": "https://api.lab.local",
    "feature_flags": {"new_ui": True},
    "analytics_key": BY_ID["config-leak"].flag,   # should never be client-side
}

TRANSACTION_PIN = "4271"   # VULN: 4 digits, no lockout


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def _decode_jwt_unverified(token: str) -> dict:
    """VULN: decode without verifying the signature, and honor alg=none."""
    try:
        header_b64, payload_b64, _sig = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return {}
    # A correct implementation would reject alg=none and verify the signature.
    if header.get("alg", "").lower() == "none":
        return payload
    return payload  # still unverified — the whole point of the challenge


def handle(method: str, path: str, headers: dict, body: bytes) -> tuple[int, dict]:
    """Return (status_code, json_body). Pure and socket-free for testability."""
    route = urlparse(path).path

    if method == "GET" and route == "/api/config":
        return 200, APP_CONFIG

    if method == "GET" and route.startswith("/api/users/") and route.endswith("/profile"):
        uid = route.split("/")[3]
        user = USERS.get(uid)
        if user is None:
            return 404, {"error": "no such user"}
        # VULN: no check that the caller *is* this user.
        return 200, user

    if method == "POST" and route == "/api/login":
        data = _json(body)
        # trivial: any non-empty username "succeeds" and gets a token
        if data.get("username"):
            return 200, {"token": _issue_demo_token(data["username"], role="user")}
        return 401, {"error": "missing username"}

    if method == "GET" and route == "/api/admin":
        token = (headers.get("authorization", "") or "").removeprefix("Bearer ").strip()
        claims = _decode_jwt_unverified(token)
        if claims.get("role") == "admin":
            return 200, {"secret": BY_ID["jwt-none"].flag, "claims": claims}
        return 403, {"error": "admin only"}

    if method == "POST" and route == "/api/transfer":
        data = _json(body)
        # VULN: no rate limiting / lockout on the PIN.
        if str(data.get("pin", "")) == TRANSACTION_PIN:
            return 200, {"ok": True, "flag": BY_ID["weak-pin"].flag}
        return 403, {"error": "wrong pin"}

    return 404, {"error": "not found"}


def _json(body: bytes) -> dict:
    try:
        return json.loads(body or b"{}")
    except ValueError:
        return {}


def _issue_demo_token(username: str, role: str) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}))
    payload = _b64(json.dumps({"sub": username, "role": role}))
    return f"{header}.{payload}.demo-signature"


def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


class _Handler(BaseHTTPRequestHandler):
    def _dispatch(self, method: str):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        hdrs = {k.lower(): v for k, v in self.headers.items()}
        status, payload = handle(method, self.path, hdrs, body)
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):   # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def log_message(self, *args):  # quiet
        pass


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:  # pragma: no cover
    server = HTTPServer((host, port), _Handler)
    print(f"dvmobile vulnerable lab server on http://{host}:{port}  (training only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
