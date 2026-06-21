"""dvmobile CLI.

    dvmobile challenges                 list the challenges
    dvmobile serve [--port 8000]        run the vulnerable lab server
    dvmobile submit <id> <flag>         submit a flag
    dvmobile score                      show progress
"""

from __future__ import annotations

import argparse
from typing import Optional

from .challenges import CHALLENGES, get
from .scoring import Scoreboard

DEFAULT_BOARD = ".dvmobile_score.json"


def cmd_challenges(args):
    for c in CHALLENGES:
        print(f"{c.id:16} [{c.difficulty:6}] {c.category:8} {c.masvs:14} {c.title}")
        if args.hints:
            print(f"                 hint: {c.hint}")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dvmobile", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    p_ch = sub.add_parser("challenges", help="list challenges")
    p_ch.add_argument("--hints", action="store_true")
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
