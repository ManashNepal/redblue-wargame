import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from game_controller import BASE_URL, KNOWN_VULNERABILITIES, GameResult, run_game

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_FILE = "target_app/app.py"


@dataclass
class RunRecord:
    """The outcome of one replayed match."""

    index: int
    patched: list[str]
    total: int
    rounds: int
    stop_reason: str | None
    elapsed_s: float


@dataclass
class DeterministicSummary:
    """Aggregate metrics across all runs."""

    runs: int
    full_sweeps: int
    avg_patched: float
    total: int
    avg_sweep_rounds: float | None
    per_vuln_fixed: dict[str, int]  # vuln id -> number of runs it was fixed in


def reset_target(base_url: str = BASE_URL) -> None:
    """Revert the target app to its committed, fully-vulnerable state."""
    subprocess.run(
        ["git", "-C", str(REPO_ROOT), "checkout", "--", TARGET_FILE],
        check=True,
        capture_output=True,
    )
    wait_until_vulnerable(base_url)


def wait_until_vulnerable(base: str, timeout_s: float = 20.0) -> None:
    """Poll until the reverted app has reloaded."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{base}/admin", timeout=5).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise RuntimeError(
        f"Target at {base} did not return to its vulnerable state within "
        f"{timeout_s:.0f}s after reset. Is it running with --reload?"
    )


def play_match(index: int, base_url: str, rounds: int, timeout: int) -> RunRecord:
    """Reset the app, play one match, and record the outcome."""
    reset_target(base_url)
    start = time.monotonic()
    result: GameResult = run_game(
        base_url=base_url, max_rounds=rounds, time_budget_s=timeout, on_event=None
    )
    return RunRecord(
        index=index,
        patched=result.patched,
        total=result.total,
        rounds=result.rounds,
        stop_reason=result.stop_reason,
        elapsed_s=round(time.monotonic() - start, 1),
    )


def play_matches(
    runs: int,
    base_url: str,
    rounds: int,
    timeout: int,
    on_run: "callable | None" = None,
) -> list[RunRecord]:
    """Play `runs` matches back to back, returning one record each."""
    records: list[RunRecord] = []
    for i in range(1, runs + 1):
        record = play_match(i, base_url, rounds, timeout)
        records.append(record)
        if on_run:
            on_run(record)
    return records


def summarize(records: list[RunRecord]) -> DeterministicSummary:
    """Reduce per-run records to aggregate metrics."""
    n = len(records)
    total = len(KNOWN_VULNERABILITIES)
    patched_counts = [len(r.patched) for r in records]
    full_sweeps = sum(1 for c in patched_counts if c == total)
    sweep_rounds = [r.rounds for r in records if len(r.patched) == total]
    per_vuln = {
        vuln.id: sum(1 for r in records if vuln.id in r.patched)
        for vuln in KNOWN_VULNERABILITIES
    }
    return DeterministicSummary(
        runs=n,
        full_sweeps=full_sweeps,
        avg_patched=sum(patched_counts) / n if n else 0.0,
        total=total,
        avg_sweep_rounds=(
            sum(sweep_rounds) / len(sweep_rounds) if sweep_rounds else None
        ),
        per_vuln_fixed=per_vuln,
    )
