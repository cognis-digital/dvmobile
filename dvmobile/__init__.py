"""dvmobile — a deliberately-vulnerable mobile backend lab for training.

Bundles an intentionally-insecure API (``vulnserver``), a catalog of documented
mobile/API security challenges with writeups (``challenges``), and a flag-based
scoreboard (``scoring``). For learning and authorized practice only.
"""

from .challenges import Challenge, CHALLENGES, BY_ID, get
from .vulnserver import handle, serve
from .scoring import Scoreboard

__all__ = ["Challenge", "CHALLENGES", "BY_ID", "get", "handle", "serve", "Scoreboard"]

__version__ = "0.1.0"
