import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from strands.multiagent import GraphBuilder
from strands.multiagent.base import MultiAgentBase, MultiAgentResult, Status

from agents.blue_team import build_blue_swarm
from agents.red_team import build_red_swarm
from agents.tools import LOG_PATH

BASE_URL = "http://localhost:8001"
MAX_ROUNDS = 3
TIME_BUDGET_SECONDS = 300  # 5 minutes

GAME_TASK = (
    "Begin the security engagement against the target application. "
    "Red team, assess it; blue team, defend it."
)


# Functions to check whether the issues were patched
def _check_admin_bypass(base: str) -> bool:
    """Issue patched when /admin rejects an unauthenticated request."""
    r = httpx.get(f"{base}/admin", timeout=10)
    return r.status_code in (401, 403)  # 401 - unauthenticated, 403 - unauthorized


def _check_sql_injection(base: str) -> bool:
    """Issue patched when a single quote no longer returns 500 error code and a tautology returns no rows."""
    quote = httpx.get(f"{base}/search", params={"q": "'"}, timeout=10)
    tautology = httpx.get(f"{base}/search", params={"q": "' OR '1'='1"}, timeout=10)
    if quote.status_code != 200:
        return False
    try:
        rows = tautology.json()
    except ValueError:
        return False
    return isinstance(rows, list) and len(rows) == 0


def _check_session_hijack(base: str) -> bool:
    """Issue patched when a guessed/forged token is rejected."""
    r = httpx.get(
        f"{base}/account",
        headers={"Authorization": "Bearer session-1"},
        timeout=10,
    )
    return r.status_code == 401


def _login_ms(base: str, username: str) -> float:
    """Elapsed ms for a failed login attempt with the given username."""
    start = time.perf_counter()
    httpx.post(
        f"{base}/login",
        json={"username": username, "password": "wrong-password-xyz"},
        timeout=10,
    )
    return (time.perf_counter() - start) * 1000


def _check_timing_attack(base: str, samples: int = 5, max_gap_ms: float = 15.0) -> bool:
    """Issue patched when a known-real username is not meaningfully slower than a fake one.

    Vulnerable app: real users hit the password hash (~35 ms of PBKDF2) while
    unknown users return instantly, so the gap is large.
    Fixed app: both hash, so the gap collapses toward zero.
    """
    real = sum(_login_ms(base, "admin") for _ in range(samples)) / samples
    fake = sum(_login_ms(base, "zzz_no_such_user_qq") for _ in range(samples)) / samples
    return (real - fake) < max_gap_ms


@dataclass
class Vulnerability:
    id: str
    description: str
    is_patched: Callable[[str], bool]


KNOWN_VULNERABILITIES: list[Vulnerability] = [
    Vulnerability("admin_bypass", "/admin has no auth check", _check_admin_bypass),
    Vulnerability(
        "sql_injection",
        "/search uses raw string-interpolated SQL",
        _check_sql_injection,
    ),
    Vulnerability(
        "session_hijack",
        "predictable, non-expiring session-<id> tokens",
        _check_session_hijack,
    ),
    Vulnerability(
        "timing_attack", "/login is faster for unknown users", _check_timing_attack
    ),
]


def score_round(base_url: str) -> set[str]:
    """Return the ids of vulnerabilities currently patched."""
    patched: set[str] = set()
    for vuln in KNOWN_VULNERABILITIES:
        try:
            if vuln.is_patched(base_url):
                patched.add(vuln.id)
        except (
            httpx.HTTPError,
            ValueError,
        ):  # if the check errors, treat as not patched
            pass
    return patched


# Scorer node: a deterministic Python step wrapped as a graph node
class ScoreRoundNode(MultiAgentBase):
    """Score one round: test the app for fixed vulnerabilities and decide whether to loop again."""

    def __init__(
        self,
        base_url: str,
        max_rounds: int,
        time_budget_s: float,
        on_event: Callable[[dict], None] | None = None,
        id: str = "score",
    ) -> None:
        super().__init__()
        self.id = id
        self.base_url = base_url
        self.max_rounds = max_rounds
        self.time_budget_s = time_budget_s
        self.on_event = on_event
        self.start_time = time.monotonic()
        self.round_number = 0
        self.patched_ids: set[str] = set()
        self.all_patched = False
        self.should_continue = True
        self.stop_reason: str | None = None
        self.round_events: list[dict] = []

    async def invoke_async(
        self, task: Any, invocation_state: dict[str, Any] | None = None, **kwargs: Any
    ) -> MultiAgentResult:
        self.round_number += 1
        self.patched_ids = await asyncio.to_thread(score_round, self.base_url)
        total = len(KNOWN_VULNERABILITIES)
        self.all_patched = len(self.patched_ids) == total
        elapsed = time.monotonic() - self.start_time

        if self.all_patched:
            self.should_continue, self.stop_reason = False, "all_patched"
        elif self.round_number >= self.max_rounds:
            self.should_continue, self.stop_reason = False, "max_rounds"
        elif elapsed >= self.time_budget_s:
            self.should_continue, self.stop_reason = False, "timeout"
        else:
            self.should_continue, self.stop_reason = True, None

        event = {
            "round": self.round_number,
            "patched": sorted(self.patched_ids),
            "total": total,
            "all_patched": self.all_patched,
            "elapsed_s": round(elapsed, 1),
            "continuing": self.should_continue,
            "stop_reason": self.stop_reason,
        }
        self.round_events.append(event)
        if self.on_event:
            self.on_event(event)

        return MultiAgentResult(status=Status.COMPLETED, execution_count=1)


# Graph assembly and entry point.
@dataclass
class GameResult:
    stop_reason: str | None
    rounds: int
    patched: list[str]
    total: int
    events: list[dict] = field(default_factory=list)


def run_game(
    base_url: str = BASE_URL,
    max_rounds: int = MAX_ROUNDS,
    time_budget_s: float = TIME_BUDGET_SECONDS,
    on_event: Callable[[dict], None] | None = None,
) -> GameResult:
    """Run the full match and return the outcome.

    Graph shape (cyclic):
        red -> blue -> score -> (back to red while should_continue) -> ... -> end
    """
    LOG_PATH.unlink(missing_ok=True)

    red = build_red_swarm()
    blue = build_blue_swarm()
    score = ScoreRoundNode(base_url, max_rounds, time_budget_s, on_event)

    builder = GraphBuilder()
    builder.add_node(red, "red")
    builder.add_node(blue, "blue")
    builder.add_node(score, "score")
    builder.set_entry_point("red")
    builder.add_edge("red", "blue")
    builder.add_edge("blue", "score")
    builder.add_edge("score", "red", condition=lambda state: score.should_continue)
    builder.reset_on_revisit(True)
    # Hard safety backstops
    builder.set_max_node_executions(3 * max_rounds + 3)
    builder.set_execution_timeout(time_budget_s * 2 + 300)
    builder.set_node_timeout(600)

    graph = builder.build()
    graph(GAME_TASK)

    return GameResult(
        stop_reason=score.stop_reason,
        rounds=score.round_number,
        patched=sorted(score.patched_ids),
        total=len(KNOWN_VULNERABILITIES),
        events=score.round_events,
    )
