# dvmobile — Damn Vulnerable Mobile

**A self-contained, intentionally-vulnerable mobile backend lab for security
training — now wired to a 262k-record offline vulnerability database so every
challenge maps to the *real* CVEs it teaches.**

`dvmobile` ships a deliberately-insecure API, a catalog of documented mobile/API
security challenges (mapped to **OWASP MASVS** + **CWE**), a flag-based
scoreboard, and a bundled offline OSV database (~262k real vulns) so each lab
weakness links to genuine production CVEs you can look up without a network.
Pure standard library — **nothing to install, no Docker required.**

> ⚠️ **Training only.** Every weakness here is intentional and contained to the
> bundled server. Run it locally. Don't expose it; don't copy these patterns
> into real code — recognizing them is the point. `dvmobile` is **passive and
> offline**: it never scans, probes, or contacts a live target.

## What's in the box

| Piece | What it does |
|-------|--------------|
| `dvmobile serve` | An intentionally-insecure HTTP API (the lab target) |
| `challenges/` | Four MASVS-mapped writeups: exploit + fix + **real-world CVEs** |
| `dvmobile cve` / `enrich` / `match` | Offline lookups against a **262k-record OSV DB** |
| `dvmobile feeds` | Edge / air-gap refresh catalog (CISA KEV, EPSS, OSV, NVD, GHSA) |
| `ports/` | Go, TypeScript/Node, and POSIX-shell ports of the CLI surface |

## Quickstart

```bash
pip install -e .          # or: git clone … && pip install -e .

# 1) See the challenges, with the CWE + real-world CVEs each one teaches
dvmobile challenges --cves

# 2) Run the vulnerable lab
dvmobile serve --port 8000

# 3) ...attack it (see challenges/), then capture flags
dvmobile submit idor-profile 'DVM{...}'
dvmobile score

# 4) Pivot from a lab weakness to the real CVEs — fully offline
dvmobile enrich jwt-none
dvmobile cve CVE-2021-44228
```

## Challenges

| id | MASVS | CWE | Difficulty | Flaw |
|----|-------|-----|-----------|------|
| `idor-profile` | MASVS-AUTH-1 | CWE-639 | easy | IDOR — read another user's profile |
| `config-leak`  | MASVS-STORAGE-1 | CWE-798 | easy | Secret leaked in client bootstrap config |
| `jwt-none`     | MASVS-AUTH-2 | CWE-347 | medium | `alg=none` / unverified JWT → admin takeover |
| `weak-pin`     | MASVS-AUTH-3 | CWE-307 | medium | Unthrottled 4-digit PIN brute force |

Each has a full writeup with exploit, fix, **and the real-world CVEs that share
the weakness class** under [`challenges/`](challenges/).

## Bundled offline vulnerability DB (262k real OSV records)

The lab teaches *weakness classes*. To make that concrete, every challenge
references **real, public** CVE/GHSA advisories for the same bug class — and all
of them resolve in the bundled, gzipped OSV corpus
(`dvmobile/cognis_vulndb.jsonl.gz`, ~262,000 records across
PyPI / npm / Go / Maven / RubyGems / crates.io / NuGet). No network, no key.

```bash
# Resolve a CVE or GHSA id straight from the bundle
$ dvmobile cve CVE-2021-44228
GHSA-jfh8-c2jp-5v3q  [Maven]  CVE-2021-44228
  Remote code injection in Log4j
  severity: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H
  packages: org.apache.logging.log4j:log4j-core, …

# Show the real CVEs behind a lab challenge
$ dvmobile enrich idor-profile
idor-profile  MASVS-AUTH-1  CWE-639  (4 CVEs resolved offline)
  CVE-2023-32078     [Go       ] Netmaker IDOR Allows User to Update Other User's Password
  CVE-2022-21713     [Go       ] Grafana API IDOR
  CVE-2025-64523     [Go       ] File Browser is Vulnerable to Insecure Direct Object Reference (IDOR)
  CVE-2026-40077     [Go       ] Beszel has an IDOR in hub API endpoints reading the id from the URL

# Match SBOM-style component names against the DB (substring-tolerant)
$ dvmobile match org.apache.logging.log4j:log4j-core lodash --limit 3
org.apache.logging.log4j:log4j-core: 11 known vuln(s) in the bundled DB
  CVE-2021-44228     [Maven    ] Remote code injection in Log4j
  CVE-2021-45046     [Maven    ] Incomplete fix for Apache Log4j vulnerability
  CVE-2017-5645      [Maven    ] Deserialization of Untrusted Data in Log4j
```

JSON output is available everywhere with `--json` for piping into other tools.

### Edge / air-gap refresh

The 262k bundle is the **offline baseline** — clone the repo and it works on a
disconnected enclave immediately. To refresh or extend it on a machine that
*does* have connectivity, then sneakernet the result to the air gap, use the
keyless feeds catalog:

```bash
dvmobile feeds --domain vuln                       # CISA KEV, EPSS, OSV, NVD, GHSA…
python -m dvmobile.datafeeds update cisa-kev epss  # fetch + cache to disk
python -m dvmobile.datafeeds get osv --offline     # serve from cache, no network
python -m dvmobile.datafeeds snapshot-export feeds.tar.gz   # carry to the air gap
python -m dvmobile.datafeeds snapshot-import feeds.tar.gz   # import on the enclave
```

`datafeeds` is standard-library-only, caches to `~/.cache/cognis-feeds`
(override with `COGNIS_FEEDS_CACHE`), and `--offline` never touches the network.

## Language ports

The core CLI surface (`challenges`, `cve`, `enrich`) is mirrored in three other
languages under [`ports/`](ports/), each reading the **same** bundled OSV DB and
the shared `ports/challenges.json` catalog. Each ships a smoke test, and a CI job
([`.github/workflows/ports.yml`](.github/workflows/ports.yml)) builds and tests
all three on every push.

| Port | Run | Test |
|------|-----|------|
| Go ([`ports/go`](ports/go)) | `go run . cve CVE-2021-44228` | `go test ./...` |
| TypeScript/Node ([`ports/node`](ports/node)) | `npm run build && node dist/dvmobile.js challenges` | `npm test` |
| POSIX shell ([`ports/shell`](ports/shell)) | `sh dvmobile.sh cve CVE-2021-44228` | `sh test_dvmobile.sh` |

## Why it's testable

The server's request logic is a pure function (`dvmobile.vulnserver.handle`), so
the bundled test-suite *is* a set of reference exploits — each test recovers a
flag the intended way and submits it. The DB/enrich tests prove **real** offline
lookups (e.g. `CVE-2021-44228` / log4j resolves). `pytest` passing means the lab,
the writeups, and the CVE references stay consistent.

```bash
pip install -e ".[dev]" && python -m pytest -q     # 80+ tests, 150+ assertions
```

## Use as a teaching tool

- **Self-study:** `serve`, attack, `submit`, compare your fix to the writeup,
  then `enrich` the challenge to read the real CVEs that shipped the same bug.
- **Workshops / CTF:** hand out the repo, score with the shared board file.
- **AppSec onboarding:** `dvmobile match <your component list>` against the
  offline DB to demonstrate SBOM-style triage with zero connectivity.
- Pairs nicely with [`apkprobe`](../apkprobe) (static analysis) and
  [`rootsentry`](../rootsentry) (runtime integrity) from the same suite.

## Scope, authorization & safety

- **Defensive / authorized-use only.** The lab target is the bundled server and
  nothing else.
- **No active scanning.** `dvmobile` reads local data (the bundled DB and the
  feed cache); it never probes or exploits a remote host. The `serve` command
  binds `127.0.0.1` by default.
- **No fabricated data.** Every CVE/GHSA reference is real and resolves in the
  bundled OSV corpus; nothing is invented.
- Run the deliberately-insecure server **locally only** — never expose it.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
