# 02 — Sensitive data exposure in API config

**Category:** Storage / Data exposure · **MASVS-STORAGE-1** · **Difficulty:** easy

## The flaw
`GET /api/config` returns a bootstrap config the mobile client fetches at
launch. It embeds `analytics_key` — a secret that should live server-side only.
Anything shipped to or fetched by the client is recoverable by anyone.

## Exploit
```bash
curl http://127.0.0.1:8000/api/config   # flag is the analytics_key
```

## Fix
Never send secrets to the client. Keep third-party keys server-side and proxy
the calls, or use short-lived, scoped tokens minted per request. Treat the
mobile app as fully observable by the user.

## Real-world CVE context (CWE-798)

Hard-coded / client-shipped secrets are a recurring, high-impact class. All ids
resolve in the bundled offline OSV DB (`dvmobile cve <id>`):

| CVE | Project | What broke |
|-----|---------|------------|
| `CVE-2021-43116` | Alibaba Nacos | Use of hard-coded credentials |
| `CVE-2021-45458` | Apache Kylin | Use of hard-coded credentials |
| `CVE-2023-32077` | Netmaker | Hard-coded DNS secret key |
| `CVE-2022-39273` | flyteadmin | Hard-coded hashed password |

```bash
dvmobile cve CVE-2021-43116
dvmobile enrich config-leak
```

Same root cause as the lab's `analytics_key`: a secret that lives somewhere the
attacker can read.
