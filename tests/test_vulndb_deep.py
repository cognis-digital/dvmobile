"""Deeper offline coverage of the bundled OSV vuln DB loader."""

import gzip
import json

import pytest

from dvmobile.vulndb_local import VulnDB, count


DB = VulnDB()


def test_count_is_262k():
    assert DB.count() >= 260000


def test_module_level_count_helper():
    assert count() == VulnDB().count()


def test_iter_yields_dicts():
    it = iter(VulnDB())
    first = next(it)
    assert isinstance(first, dict)
    assert first["id"]


def test_load_is_cached():
    db = VulnDB()
    a = db.load()
    b = db.load()
    assert a is b  # second call returns the cached list


def test_records_have_expected_schema():
    db = VulnDB()
    sample = db.load()[:200]
    for r in sample:
        for key in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
            assert key in r
        assert isinstance(r["aliases"], list)
        assert isinstance(r["packages"], list)


def test_by_cve_log4j_known_package():
    hits = DB.by_cve("CVE-2021-44228")
    assert hits
    pkgs = hits[0]["packages"]
    assert any("log4j-core" in p for p in pkgs)


def test_by_cve_returns_empty_for_unknown():
    assert DB.by_cve("CVE-1999-99999") == []
    assert DB.by_cve("") == []


def test_by_cve_indexes_both_id_and_aliases():
    # the GHSA id and its CVE alias should reach the same record
    by_ghsa = DB.by_cve("GHSA-jfh8-c2jp-5v3q")
    by_cve = DB.by_cve("CVE-2021-44228")
    assert by_ghsa and by_cve
    assert by_ghsa[0]["id"] == by_cve[0]["id"]


def test_by_package_lodash_or_django():
    db = VulnDB()
    assert db.by_package("lodash") or db.by_package("django")


def test_by_package_ecosystem_filter_consistent():
    db = VulnDB()
    name = "org.apache.logging.log4j:log4j-core"
    allhits = db.by_package(name)
    maven = db.by_package(name, ecosystem="Maven")
    assert len(maven) <= len(allhits)
    for r in maven:
        assert r["ecosystem"].lower() == "maven"


def test_by_package_unknown_empty():
    assert VulnDB().by_package("xyzzy-not-real-pkg") == []
    assert VulnDB().by_package("") == []


def test_search_limit_respected():
    hits = VulnDB().search("injection", limit=5)
    assert len(hits) <= 5
    for h in hits:
        assert "injection" in (h["summary"] or "").lower()


def test_search_case_insensitive():
    a = VulnDB().search("Deserialization", limit=3)
    assert all("deserialization" in (h["summary"] or "").lower() for h in a)


def test_missing_db_path_is_graceful():
    db = VulnDB(path="does-not-exist.jsonl.gz")
    assert db.count() == 0
    assert db.by_cve("CVE-2021-44228") == []
    assert list(iter(db)) == []


def test_custom_db_path(tmp_path):
    p = tmp_path / "mini.jsonl.gz"
    rec = {"id": "TEST-1", "aliases": ["CVE-2099-0001"], "ecosystem": "PyPI",
           "summary": "synthetic fixture", "severity": "", "packages": ["demo"]}
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    db = VulnDB(path=str(p))
    assert db.count() == 1
    assert db.by_cve("CVE-2099-0001")[0]["id"] == "TEST-1"
    assert db.by_package("demo")


@pytest.mark.parametrize("cve", [
    "CVE-2021-44228",   # log4j
    "GHSA-jfh8-c2jp-5v3q",
])
def test_known_ids_resolve(cve):
    assert DB.by_cve(cve)
