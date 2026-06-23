# dvmobile challenges

Four deliberately-planted weaknesses in the bundled lab server, each mapped to
**OWASP MASVS**, a primary **CWE**, and the **real, public CVEs** that shipped
the same bug class in production software. Every CVE referenced below resolves in
the bundled offline OSV DB — verify with `dvmobile cve <id>` or
`dvmobile enrich <challenge-id>`.

| # | Challenge | MASVS | CWE | Real-world CVEs (offline-resolvable) |
|---|-----------|-------|-----|--------------------------------------|
| 01 | [IDOR — read another user's profile](01-idor-profile.md) | MASVS-AUTH-1 | CWE-639 | CVE-2023-32078, CVE-2022-21713, CVE-2025-64523, CVE-2026-40077 |
| 02 | [Sensitive data exposure in API config](02-config-leak.md) | MASVS-STORAGE-1 | CWE-798 | CVE-2021-43116, CVE-2021-45458, CVE-2023-32077, CVE-2022-39273 |
| 03 | [alg=none / forged-role JWT](03-jwt-none.md) | MASVS-AUTH-2 | CWE-347 | CVE-2015-9235, CVE-2015-10004, CVE-2023-22463, CVE-2026-48031 |
| 04 | [Brute-forceable transaction PIN](04-weak-pin.md) | MASVS-AUTH-3 | CWE-307 | CVE-2024-21652, CVE-2024-24767, CVE-2025-60538, CVE-2026-26233 |

## Workflow

```bash
dvmobile serve --port 8000          # start the lab
# ...exploit the endpoint per the writeup...
dvmobile submit <id> 'DVM{...}'     # capture the flag
dvmobile enrich <id>                # study the real CVEs behind the bug class
```

Each writeup contains: **the flaw**, a **copy-pasteable exploit**, the **fix**,
and a **Real-world CVE context** table backed by the offline DB.
