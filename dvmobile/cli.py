"""dvmobile CLI.

    dvmobile challenges                 list the challenges
    dvmobile serve [--port 8000]        run the vulnerable lab server
    dvmobile submit <id> <flag>         submit a flag
    dvmobile score                      show progress
    dvmobile cve <id>                   look up a CVE/GHSA in the offline DB
    dvmobile enrich [id]                real-world CVE context for challenge(s)
    dvmobile match <pkg ...>            match components vs the offline OSV DB
    dvmobile feeds [--domain ...]       list edge/air-gap intelligence feeds
"""

from __future__ import annotations

import argparse
import json
from typing import Optional

from .challenges import CHALLENGES, get
from .scoring import Scoreboard

DEFAULT_BOARD = ".dvmobile_score.json"


def cmd_challenges(args):
    for c in CHALLENGES:
        print(f"{c.id:16} [{c.difficulty:6}] {c.category:8} {c.masvs:14} {c.title}")
        if args.hints:
            print(f"                 hint: {c.hint}")
        if getattr(args, "cves", False) and c.real_world_cves:
            print(f"                 cwe: {c.cwe}  real-world: {', '.join(c.real_world_cves)}")
    return 0


def cmd_serve(args):  # pragma: no cover - blocks on a socket
    from .vulnserver import serve
    serve(port=args.port)
    return 0


def cmd_submit(args):
    board = Scoreboard(args.board)
    if get(args.id) is None:
        print(f"unknown challenge: {args.id}")
        return 2
    if board.submit(args.id, args.flag):
        print(f"correct! {board.progress()}")
        return 0
    print("incorrect flag")
    return 1


def cmd_score(args):
    board = Scoreboard(args.board)
    print(board.progress())
    for c in CHALLENGES:
        mark = "x" if board.solved.get(c.id) else " "
        print(f"  [{mark}] {c.id}")
    return 0


def cmd_cve(args):
    from .vulndb_local import VulnDB
    hits = VulnDB().by_cve(args.id)
    if not hits:
        print(f"no match for {args.id} in the bundled offline DB")
        return 1
    if args.json:
        print(json.dumps(hits, indent=2))
        return 0
    for r in hits:
        aliases = ", ".join(r.get("aliases") or [])
        print(f"{r.get('id')}  [{r.get('ecosystem','')}]  {aliases}")
        print(f"  {r.get('summary','')}")
        if r.get("severity"):
            print(f"  severity: {r['severity']}")
        pkgs = r.get("packages") or []
        if pkgs:
            print(f"  packages: {', '.join(pkgs[:8])}")
    return 0


def cmd_enrich(args):
    from .enrich import enrich_challenge, enrich_challenges
    if args.id:
        ch = get(args.id)
        if ch is None:
            print(f"unknown challenge: {args.id}")
            return 2
        result = [enrich_challenge(ch)]
    else:
        result = enrich_challenges()
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    for e in result:
        print(f"{e['id']}  {e['masvs']}  {e['cwe']}  ({len(e['resolved'])} CVEs resolved offline)")
        for m in e["matches"]:
            print(f"  {m['cve'] or m['id']:18} [{m['ecosystem']:9}] {m['summary'][:70]}")
        if e["unresolved"]:
            print(f"  (unresolved in bundle: {', '.join(e['unresolved'])})")
    return 0


def cmd_match(args):
    from .enrich import enrich_components
    result = enrich_components(args.packages, ecosystem=args.ecosystem)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    for name, hits in result.items():
        print(f"{name}: {len(hits)} known vuln(s) in the bundled DB")
        for m in hits[: args.limit]:
            print(f"  {m['cve'] or m['id']:18} [{m['ecosystem']:9}] {m['summary'][:70]}")
    return 0


def cmd_feeds(args):
    from . import datafeeds
    feeds = datafeeds.list_feeds(args.domain)
    if not feeds:
        print("no feeds in catalog" + (f" for domain {args.domain!r}" if args.domain else ""))
        return 1
    for f in feeds:
        print(f"  {f['id']:28} {f.get('domain',''):13} {f.get('format',''):6} {f['name']}")
    print(f"\n{len(feeds)} feed(s). Refresh offline-capable: python -m dvmobile.datafeeds update <id>")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dvmobile", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    p_ch = sub.add_parser("challenges", help="list challenges")
    p_ch.add_argument("--hints", action="store_true")
    p_ch.add_argument("--cves", action="store_true", help="show CWE + real-world CVE refs")
    p_ch.set_defaults(func=cmd_challenges)

    p_sv = sub.add_parser("serve", help="run the vulnerable lab server")
    p_sv.add_argument("--port", type=int, default=8000)
    p_sv.set_defaults(func=cmd_serve)

    p_sb = sub.add_parser("submit", help="submit a flag")
    p_sb.add_argument("id")
    p_sb.add_argument("flag")
    p_sb.add_argument("--board", default=DEFAULT_BOARD)
    p_sb.set_defaults(func=cmd_submit)

    p_sc = sub.add_parser("score", help="show progress")
    p_sc.add_argument("--board", default=DEFAULT_BOARD)
    p_sc.set_defaults(func=cmd_score)

    p_cve = sub.add_parser("cve", help="look up a CVE/GHSA in the offline DB")
    p_cve.add_argument("id")
    p_cve.add_argument("--json", action="store_true")
    p_cve.set_defaults(func=cmd_cve)

    p_en = sub.add_parser("enrich", help="real-world CVE context for challenge(s)")
    p_en.add_argument("id", nargs="?", default=None)
    p_en.add_argument("--json", action="store_true")
    p_en.set_defaults(func=cmd_enrich)

    p_m = sub.add_parser("match", help="match components against the offline OSV DB")
    p_m.add_argument("packages", nargs="+")
    p_m.add_argument("--ecosystem", default=None)
    p_m.add_argument("--limit", type=int, default=10)
    p_m.add_argument("--json", action="store_true")
    p_m.set_defaults(func=cmd_match)

    p_f = sub.add_parser("feeds", help="list edge/air-gap intelligence feeds")
    p_f.add_argument("--domain", default=None)
    p_f.set_defaults(func=cmd_feeds)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        from . import __version__
        print(__version__)
        return 0
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
