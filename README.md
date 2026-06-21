# dvmobile — Damn Vulnerable Mobile

**A self-contained, intentionally-vulnerable mobile backend lab for security training.**

`dvmobile` ships a deliberately-insecure API, a catalog of documented
mobile/API security challenges (mapped to **OWASP MASVS**), and a flag-based
scoreboard. Spin it up, attack it, capture flags, read the writeup for the
proper fix. Pure standard library — **nothing to install, no Docker required.**

> ⚠️ **Training only.** Every weakness here is intentional and contained to the
> bundled server. Run it locally. Don't expose it; don't copy these patterns
> into real code — recognizing them is the point.

## Quickstart

```bash
pip install -e .

# See the challenges
dvmobile challenges --hints

# Run the vulnerable lab
dvmobile serve --port 8000

# ...attack it (see challenges/), then submit a flag
dvmobile submit idor-profile 'DVM{...}'
dvmobile score
```

## Challenges

| id | MASVS | Difficulty | Flaw |
|----|-------|-----------|------|
| `idor-profile` | MASVS-AUTH-1 | easy | IDOR — read another user's profile |
| `config-leak`  | MASVS-STORAGE-1 | easy | Secret leaked in client bootstrap config |
| `jwt-none`     | MASVS-AUTH-2 | medium | `alg=none` / unverified JWT → admin takeover |
| `weak-pin`     | MASVS-AUTH-3 | medium | Unthrottled 4-digit PIN brute force |

Each has a full writeup with exploit and fix under [`challenges/`](challenges/).

## Why it's testable

The server's request logic is a pure function (`dvmobile.vulnserver.handle`), so
the bundled test-suite *is* a set of reference exploits — each test recovers a
flag the intended way and submits it. `pytest` passing means the lab and the
writeups stay consistent.

```bash
pip install -e ".[dev]" && python -m pytest -q
```

## Use as a teaching tool

- Self-study: `serve`, attack, `submit`, compare your fix to the writeup.
- Workshops/CTF: hand out the repo, score with the shared board file.
- Pairs nicely with [`apkprobe`](../apkprobe) (static analysis) and
  [`rootsentry`](../rootsentry) (runtime integrity) from the same suite.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
