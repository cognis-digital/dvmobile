"""Offline enrichment tests: every challenge's real-world CVE references resolve
against the bundled OSV DB, and component matching works on real packages.

These assertions are real lookups against ``cognis_vulndb.jsonl.gz`` — no
network, no fabricated data."""

import pytest

from dvmobile.challenges import CHALLENGES, BY_ID
from dvmobile.enrich import (
    enrich_challenge,
    enrich_challenges,
    enrich_components,
    enrich_cve,
)
from dvmobile.vulndb_local import VulnDB

DB = VulnDB()


# --- challenge CVE references are real and resolvable --------------------- #
def test_every_challenge_declares_cwe_and_cves():
    for c in CHALLENGES:
        assert c.cwe.startswith("CWE-"), c.id
        assert len(c.real_world_cves) >= 3, c.id


def test_every_referenced_cve_resolves_offline():
    for c in CHALLENGES:
        for cve in c.real_world_cves:
            hits = DB.by_cve(cve)
            assert hits, f"{c.id}: {cve} did not resolve in the bundled DB"


def test_no_fabricated_cve_format():
    # Every reference is a real CVE id; sanity-check the shape.
    for c in CHALLENGES:
        for cve in c.real_world_cves:
            assert cve.startswith("CVE-")
            year, num = cve.split("-")[1:3]
            assert year.isdigit() and len(year) == 4
            assert num.isdigit()


@pytest.mark.parametrize("cid", list(BY_ID))
def test_enrich_challenge_resolves_all(cid):
    e = enrich_challenge(BY_ID[cid])
    assert e["id"] == cid
    assert e["unresolved"] == []
    assert len(e["resolved"]) == len(BY_ID[cid].real_world_cves)
    assert len(e["matches"]) >= 1
    for m in e["matches"]:
        assert m["id"]
        assert "summary" in m


def test_enrich_challenges_covers_all():
    results = enrich_challenges()
    assert len(results) == len(CHALLENGES)
    assert {r["id"] for r in results} == {c.id for c in CHALLENGES}
    assert all(r["unresolved"] == [] for r in results)


def test_enrich_match_projection_fields():
    e = enrich_challenge(BY_ID["jwt-none"])
    for m in e["matches"]:
        for field in ("id", "cve", "ecosystem", "severity", "summary", "packages"):
            assert field in m
        assert isinstance(m["packages"], list)


# --- single CVE lookup ---------------------------------------------------- #
def test_enrich_cve_log4j():
    hits = enrich_cve("CVE-2021-44228")
    assert hits
    assert any("log4j" in (h["summary"] or "").lower() for h in hits)
    assert hits[0]["cve"] == "CVE-2021-44228"


def test_enrich_cve_via_ghsa_alias():
    hits = enrich_cve("GHSA-jfh8-c2jp-5v3q")
    assert hits
    assert hits[0]["id"] == "GHSA-jfh8-c2jp-5v3q"


def test_enrich_cve_case_insensitive():
    assert enrich_cve("cve-2021-44228") == enrich_cve("CVE-2021-44228")


def test_enrich_cve_unknown_empty():
    assert enrich_cve("CVE-0000-00000") == []
    assert enrich_cve("") == []


# --- component / SBOM matching ------------------------------------------- #
def test_match_log4j_core_exact():
    res = enrich_components(["org.apache.logging.log4j:log4j-core"])
    hits = res["org.apache.logging.log4j:log4j-core"]
    assert len(hits) >= 1
    assert any(h["cve"] == "CVE-2021-44228" for h in hits)


def test_match_substring_fallback():
    res = enrich_components(["log4j-core"])
    assert res["log4j-core"], "substring match should find log4j packages"


def test_match_multiple_components():
    res = enrich_components(["lodash", "django", "log4j-core"])
    assert set(res.keys()) == {"lodash", "django", "log4j-core"}
    assert any(res.values())


def test_match_ecosystem_filter():
    res = enrich_components(["org.apache.logging.log4j:log4j-core"], ecosystem="Maven")
    for h in res["org.apache.logging.log4j:log4j-core"]:
        assert h["ecosystem"].lower() == "maven"


def test_match_blank_names_skipped():
    res = enrich_components(["", "  ", "log4j-core"])
    assert "" not in res
    assert "log4j-core" in res


def test_match_unknown_component_empty_list():
    res = enrich_components(["definitely-not-a-real-package-xyzzy-123"])
    assert res["definitely-not-a-real-package-xyzzy-123"] == []
