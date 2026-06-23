# dvmobile — language ports

Each port mirrors the core CLI surface of the Python tool — `challenges`, `cve`,
and `enrich` — reading the **same** bundled offline OSV database
(`../dvmobile/cognis_vulndb.jsonl.gz`, ~262k real records) and the shared
challenge catalog (`challenges.json`). All lookups are **offline**; no port
contacts the network.

`challenges.json` is generated from the authoritative Python definitions
(`dvmobile/challenges.py`) and guarded by `tests/test_ports_parity.py`, so the
ports never drift from the source of truth.

| Port | Build | Run | Test |
|------|-------|-----|------|
| [`go/`](go) | `go build ./...` | `go run . cve CVE-2021-44228` | `go test ./...` |
| [`node/`](node) | `npm run build` | `node dist/dvmobile.js challenges --cves` | `npm test` |
| [`shell/`](shell) | — | `sh dvmobile.sh cve CVE-2021-44228` | `sh test_dvmobile.sh` |

All three are built and tested in CI on every push — see
[`../.github/workflows/ports.yml`](../.github/workflows/ports.yml).

## Example (identical behaviour across ports)

```bash
$ go run . cve CVE-2021-44228          # Go
$ node dist/dvmobile.js cve CVE-2021-44228   # Node
$ sh dvmobile.sh cve CVE-2021-44228    # shell
GHSA-jfh8-c2jp-5v3q  [Maven]  CVE-2021-44228
  Remote code injection in Log4j
```
