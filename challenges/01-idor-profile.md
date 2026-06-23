# 01 — IDOR: read another user's profile

**Category:** Authorization · **MASVS-AUTH-1** · **Difficulty:** easy

## The flaw
`GET /api/users/{id}/profile` returns the requested user record based solely on
the `id` in the URL. It never checks that the authenticated caller actually *is*
that user (or is allowed to view them). This is a classic **Insecure Direct
Object Reference** / horizontal privilege escalation.

## Exploit
```bash
curl http://127.0.0.1:8000/api/users/1/profile   # your own profile
curl http://127.0.0.1:8000/api/users/2/profile   # someone else's — flag in "note"
```

The response for user `2` includes the flag.

## Fix
Derive the user identity from the session/token, not the URL. Enforce that
`token.sub == id` (or an explicit admin grant) before returning the record.
Object-level authorization must be checked on **every** access.

## Real-world CVE context (CWE-639)

This is not a toy class of bug — it ships in production constantly. Every id
below is a **real, public** advisory and resolves in the bundled offline OSV DB
(`dvmobile cve <id>`):

| CVE | Project | What broke |
|-----|---------|------------|
| `CVE-2023-32078` | Netmaker | IDOR let a user update *another* user's password |
| `CVE-2022-21713` | Grafana | IDOR in the API exposed other tenants' data |
| `CVE-2025-64523` | File Browser | Insecure Direct Object Reference on file access |
| `CVE-2026-40077` | Beszel | IDOR in hub API endpoints reading the system id from the URL |

```bash
dvmobile cve CVE-2023-32078      # offline lookup, no network
dvmobile enrich idor-profile     # all four, resolved against the bundled DB
```

The lab endpoint reproduces the exact pattern in these CVEs: an object id taken
straight from the request with no per-object authorization check.
