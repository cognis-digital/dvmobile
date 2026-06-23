"""enrich — match dvmobile findings against the bundled offline OSV DB.

The lab teaches *weakness classes* (IDOR, alg=none JWT, hard-coded secrets,
unthrottled PIN). Each challenge carries real, public CVE/GHSA identifiers that
demonstrate the SAME weakness in production software. This module resolves those
references — and any package/component you point at it — against the bundled
``cognis_vulndb.jsonl.gz`` (262k real OSV records) **fully offline**.

Nothing here scans a live target. It reads local data only.

    from dvmobile.enrich import enrich_challenges, enrich_components
    enrich_challenges()                  # CVE context for every lab challenge
    enrich_components(["log4j-core"])    # match SBOM-style component names
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .challenges import CHALLENGES, Challenge, get
from .vulndb_local import VulnDB


def _compact(record: dict) -> dict:
    """A small, stable projection of an OSV record for output/asserts."""
    cve = next((a for a in (record.get("aliases") or []) if a.upper().startswith("CVE")), "")
    return {
        "id": record.get("id", ""),
        "cve": cve,
        "ecosystem": record.get("ecosystem", ""),
        "severity": record.get("severity", ""),
        "summary": (record.get("summary") or "")[:200],
        "packages": record.get("packages", [])[:8],
    }


def enrich_cve(cve: str, db: Optional[VulnDB] = None) -> list[dict]:
    """Resolve a single CVE/GHSA id to compact bundled-DB records (offline)."""
    db = db or VulnDB()
    return [_compact(r) for r in db.by_cve(cve)]


def enrich_challenge(challenge: Challenge, db: Optional[VulnDB] = None) -> dict:
    """Attach bundled-DB context for one challenge's real-world CVE references."""
    db = db or VulnDB()
    matches: list[dict] = []
    resolved, unresolved = [], []
    for cve in challenge.real_world_cves:
        hits = db.by_cve(cve)
        if hits:
            resolved.append(cve)
            matches.append(_compact(hits[0]))
        else:
            unresolved.append(cve)
    return {
        "id": challenge.id,
        "title": challenge.title,
        "masvs": challenge.masvs,
        "cwe": challenge.cwe,
        "resolved": resolved,
        "unresolved": unresolved,
        "matches": matches,
    }


def enrich_challenges(db: Optional[VulnDB] = None) -> list[dict]:
    """CVE context for every lab challenge, resolved against the offline DB."""
    db = db or VulnDB()
    return [enrich_challenge(c, db) for c in CHALLENGES]


def enrich_components(
    names: Iterable[str],
    *,
    ecosystem: Optional[str] = None,
    db: Optional[VulnDB] = None,
) -> dict[str, list[dict]]:
    """Match a list of component/package names (e.g. from an SBOM) to known
    vulnerabilities in the bundled DB. Substring-tolerant: a query of ``log4j``
    matches ``org.apache.logging.log4j:log4j-core``. Offline only."""
    db = db or VulnDB()
    out: dict[str, list[dict]] = {}
    for raw in names:
        name = (raw or "").strip().lower()
        if not name:
            continue
        exact = db.by_package(name, ecosystem=ecosystem)
        if exact:
            out[raw] = [_compact(r) for r in exact]
            continue
        # fall back to a coarse substring match over indexed package names
        db._index()  # noqa: SLF001 - intentional reuse of the lazy index
        seen, hits = set(), []
        for pkg, recs in db._by_pkg.items():  # noqa: SLF001
            if name in pkg:
                for r in recs:
                    rid = r.get("id")
                    if rid and rid not in seen:
                        seen.add(rid)
                        hits.append(_compact(r))
        out[raw] = hits
    return out
