"""The language ports read a shared catalog (ports/challenges.json). This guards
that it stays in lockstep with the authoritative Python challenge definitions."""

import json
from pathlib import Path

from dvmobile.challenges import CHALLENGES

_ROOT = Path(__file__).resolve().parent.parent
_CATALOG = _ROOT / "ports" / "challenges.json"


def test_catalog_exists():
    assert _CATALOG.exists()


def test_catalog_matches_python_source():
    data = json.loads(_CATALOG.read_text(encoding="utf-8"))
    assert len(data) == len(CHALLENGES)
    by_id = {d["id"]: d for d in data}
    for c in CHALLENGES:
        d = by_id[c.id]
        assert d["title"] == c.title
        assert d["masvs"] == c.masvs
        assert d["cwe"] == c.cwe
        assert d["difficulty"] == c.difficulty
        assert d["real_world_cves"] == list(c.real_world_cves)


def test_port_sources_present():
    assert (_ROOT / "ports" / "go" / "dvmobile.go").exists()
    assert (_ROOT / "ports" / "go" / "dvmobile_test.go").exists()
    assert (_ROOT / "ports" / "node" / "dvmobile.ts").exists()
    assert (_ROOT / "ports" / "node" / "dvmobile.test.ts").exists()
    assert (_ROOT / "ports" / "shell" / "dvmobile.sh").exists()
    assert (_ROOT / "ports" / "shell" / "test_dvmobile.sh").exists()


def test_ports_ci_workflow_present():
    assert (_ROOT / ".github" / "workflows" / "ports.yml").exists()
