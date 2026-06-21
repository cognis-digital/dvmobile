"""Flag verification and a simple persistent scoreboard for the lab."""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass, field

from .challenges import CHALLENGES, BY_ID


@dataclass
class Scoreboard:
    path: str
    solved: dict = field(default_factory=dict)   # challenge_id -> True

    def __post_init__(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self.solved = json.load(fh).get("solved", {})

    def submit(self, challenge_id: str, flag: str) -> bool:
        challenge = BY_ID.get(challenge_id)
        if challenge is None:
            raise KeyError(f"unknown challenge {challenge_id!r}")
        ok = hmac.compare_digest(flag.strip(), challenge.flag)
        if ok:
            self.solved[challenge_id] = True
            self._save()
        return ok

    def _save(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"solved": self.solved}, fh, indent=2)

    @property
    def score(self) -> int:
        return len(self.solved)

    @property
    def total(self) -> int:
        return len(CHALLENGES)

    def progress(self) -> str:
        return f"{self.score}/{self.total} solved"
