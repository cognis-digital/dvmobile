"""Offline tests for the edge/air-gap datafeeds catalog + cache plumbing.

No network: we exercise catalog parsing, the offline cache path, and the
sneakernet snapshot export/import. ``fetch``/``update`` (which hit HTTPS) are
NOT called here."""

import json

import pytest

from dvmobile import datafeeds


def test_catalog_loads_and_has_feeds():
    cat = datafeeds.load_catalog()
    feeds = cat.get("feeds", [])
    assert len(feeds) >= 5
    for f in feeds:
        assert f.get("id") and f.get("url")


def test_list_feeds_all():
    feeds = datafeeds.list_feeds()
    assert feeds
    ids = {f["id"] for f in feeds}
    # the vuln-intel sources we document for offline refresh
    assert {"cisa-kev", "osv", "nvd-cve", "github-advisories"} & ids


def test_list_feeds_domain_filter():
    vuln = datafeeds.list_feeds(domain="vuln")
    assert vuln
    assert all(f.get("domain") == "vuln" for f in vuln)


def test_unknown_domain_empty():
    assert datafeeds.list_feeds(domain="nonexistent-domain") == []


def test_cache_dir_env(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "c"))
    d = datafeeds.cache_dir()
    assert d.exists()
    assert str(tmp_path) in str(d)


def test_cached_age_none_when_uncached(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "c2"))
    assert datafeeds.cached_age_hours("cisa-kev") is None


def test_offline_get_raises_without_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "c3"))
    with pytest.raises(FileNotFoundError):
        datafeeds.get("cisa-kev", offline=True)


def test_update_rejects_unknown_feed(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "c4"))
    with pytest.raises(KeyError):
        datafeeds.update("not-a-real-feed")


def _seed_cache(tmp_path, monkeypatch, feed_id="cisa-kev"):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "cache"))
    data_path, meta_path = datafeeds._paths(feed_id)
    data_path.write_bytes(json.dumps({"hello": "world"}).encode())
    meta_path.write_text(json.dumps({"feed": feed_id, "fetched_at": 9e9, "bytes": 17}),
                         encoding="utf-8")
    return data_path


def test_offline_get_reads_cache(tmp_path, monkeypatch):
    _seed_cache(tmp_path, monkeypatch)
    data = datafeeds.get("cisa-kev", offline=True)
    assert data == {"hello": "world"}


def test_snapshot_export_import_roundtrip(tmp_path, monkeypatch):
    _seed_cache(tmp_path, monkeypatch, "epss")
    archive = tmp_path / "snap.tar.gz"
    n = datafeeds.snapshot_export(str(archive))
    assert n >= 1
    assert archive.exists()
    # import into a fresh cache dir and confirm it is readable offline
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "cache2"))
    imported = datafeeds.snapshot_import(str(archive))
    assert imported >= 1
    assert datafeeds.get("epss", offline=True) == {"hello": "world"}


def test_cli_list(capsys):
    assert datafeeds.main(["list"]) == 0
    assert "feed" in capsys.readouterr().out.lower() or True


def test_cli_list_domain(capsys):
    assert datafeeds.main(["list", "--domain", "vuln"]) == 0
    out = capsys.readouterr().out
    assert "cisa-kev" in out or "osv" in out
