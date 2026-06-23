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
    cwe: str = ""               # primary CWE for the weakness class
    # Real, public CVE/GHSA identifiers that demonstrate the SAME weakness class
    # in production software. Every id here resolves in the bundled offline OSV
    # DB (see ``dvmobile cve <id>``). Nothing is fabricated.
    real_world_cves: tuple = ()


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
        cwe="CWE-639",  # Authorization Bypass Through User-Controlled Key
        real_world_cves=(
            "CVE-2023-32078",  # Netmaker IDOR — update another user's password
            "CVE-2022-21713",  # Grafana API IDOR
            "CVE-2025-64523",  # File Browser IDOR
            "CVE-2026-40077",  # Beszel IDOR in hub API endpoints
        ),
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
        cwe="CWE-798",  # Use of Hard-coded Credentials
        real_world_cves=(
            "CVE-2021-43116",  # Hard-coded credentials in Nacos
            "CVE-2021-45458",  # Hard-coded credentials in Apache Kylin
            "CVE-2023-32077",  # Netmaker hardcoded DNS secret key
            "CVE-2022-39273",  # Hardcoded hashed password in flyteadmin
        ),
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
        cwe="CWE-347",  # Improper Verification of Cryptographic Signature
        real_world_cves=(
            "CVE-2015-9235",   # jsonwebtoken verification bypass (alg confusion)
            "CVE-2015-10004",  # robbert229/jwt token validation bypass
            "CVE-2023-22463",  # KubePi login with a forged JWT token
            "CVE-2026-48031",  # Hardcoded JWT secret "random" in a Go boilerplate
        ),
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
        cwe="CWE-307",  # Improper Restriction of Excessive Authentication Attempts
        real_world_cves=(
            "CVE-2024-21652",  # Bypassing rate limit / brute-force protection
            "CVE-2024-24767",  # Password brute force in CasaOS
            "CVE-2025-60538",  # Shiori auth bypass via brute force
            "CVE-2026-26233",  # Mattermost — no rate limit on login
        ),
    ),
]

BY_ID = {c.id: c for c in CHALLENGES}


def get(challenge_id: str) -> Challenge | None:
    return BY_ID.get(challenge_id)
