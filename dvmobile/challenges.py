"""Challenge catalog for the dvmobile lab.

Each challenge is a documented mobile/API security flaw with a category, a
difficulty, a writeup, and a flag that proves the solve. Flags are intentionally
discoverable by exploiting the matching weakness in ``vulnserver`` or by
analyzing the (documented) mobile-client behavior.

This is a *training* lab. The vulnerabilities are deliberate and contained to
the bundled server; nothing here targets real systems.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Challenge:
    id: str
    title: str
    category: str       # MASVS-ish bucket
    difficulty: str     # easy | medium | hard
    masvs: str
    flag: str
    writeup: str        # path under challenges/
    hint: str


CHALLENGES: list[Challenge] = [
    Challenge(
        id="idor-profile",
        title="IDOR: read another user's profile",
        category="authz",
        difficulty="easy",
        masvs="MASVS-AUTH-1",
        flag="DVM{idor_horizontal_priv_esc}",
        writeup="challenges/01-idor-profile.md",
        hint="The profile endpoint trusts the id in the URL and checks nothing else.",
    ),
    Challenge(
        id="config-leak",
        title="Sensitive data exposure in API config",
        category="storage",
        difficulty="easy",
        masvs="MASVS-STORAGE-1",
        flag="DVM{hardcoded_api_key_in_config}",
        writeup="challenges/02-config-leak.md",
        hint="Mobile apps often pull a bootstrap config. What does it include?",
    ),
    Challenge(
        id="jwt-none",
        title="Broken auth: accept alg=none / forged role",
        category="authz",
        difficulty="medium",
        masvs="MASVS-AUTH-2",
        flag="DVM{alg_none_admin_takeover}",
        writeup="challenges/03-jwt-none.md",
        hint="The admin endpoint decodes the token without verifying the signature.",
    ),
    Challenge(
        id="weak-pin",
        title="Brute-forceable 4-digit transaction PIN",
        category="auth",
        difficulty="medium",
        masvs="MASVS-AUTH-3",
        flag="DVM{no_rate_limit_pin_bruteforce}",
        writeup="challenges/04-weak-pin.md",
        hint="There is no lockout. 10000 combinations is not many.",
    ),
]

BY_ID = {c.id: c for c in CHALLENGES}


def get(challenge_id: str) -> Challenge | None:
    return BY_ID.get(challenge_id)
