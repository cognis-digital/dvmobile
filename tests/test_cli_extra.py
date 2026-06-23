"""Tests for the new CLI surface: cve / enrich / match / feeds / challenges --cves."""

import json

from dvmobile.cli import main


# --- cve ----------------------------------------------------------------- #
def test_cve_found(capsys):
    assert main(["cve", "CVE-2021-44228"]) == 0
    out = capsys.readouterr().out
    assert "log4j" in out.lower()
    assert "GHSA-jfh8-c2jp-5v3q" in out


def test_cve_json(capsys):
    assert main(["cve", "CVE-2021-44228", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list) and data
    assert data[0]["id"]


def test_cve_not_found(capsys):
    assert main(["cve", "CVE-0000-00000"]) == 1
    assert "no match" in capsys.readouterr().out


# --- enrich -------------------------------------------------------------- #
def test_enrich_all(capsys):
    assert main(["enrich"]) == 0
    out = capsys.readouterr().out
    for cid in ("idor-profile", "config-leak", "jwt-none", "weak-pin"):
        assert cid in out
    assert "resolved offline" in out


def test_enrich_one(capsys):
    assert main(["enrich", "jwt-none"]) == 0
    out = capsys.readouterr().out
    assert "MASVS-AUTH-2" in out
    assert "CWE-347" in out


def test_enrich_json(capsys):
    assert main(["enrich", "weak-pin", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["id"] == "weak-pin"
    assert data[0]["unresolved"] == []


def test_enrich_unknown(capsys):
    assert main(["enrich", "nope"]) == 2


# --- match --------------------------------------------------------------- #
def test_match_log4j(capsys):
    assert main(["match", "org.apache.logging.log4j:log4j-core"]) == 0
    assert "known vuln" in capsys.readouterr().out


def test_match_json(capsys):
    assert main(["match", "log4j-core", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "log4j-core" in data


def test_match_limit(capsys):
    assert main(["match", "log4j-core", "--limit", "2"]) == 0


# --- feeds --------------------------------------------------------------- #
def test_feeds_list(capsys):
    assert main(["feeds"]) == 0
    out = capsys.readouterr().out
    assert "feed(s)" in out


def test_feeds_domain_filter(capsys):
    assert main(["feeds", "--domain", "vuln"]) == 0
    out = capsys.readouterr().out
    assert "cisa-kev" in out or "osv" in out


# --- challenges --cves --------------------------------------------------- #
def test_challenges_cves_flag(capsys):
    assert main(["challenges", "--cves"]) == 0
    out = capsys.readouterr().out
    assert "CWE-" in out
    assert "CVE-2021-43116" in out  # a config-leak reference


def test_help_when_no_command(capsys):
    assert main([]) == 1
