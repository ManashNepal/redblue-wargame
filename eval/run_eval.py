import click
from rich.console import Console

from game_controller import BASE_URL, MAX_ROUNDS, TIME_BUDGET_SECONDS

console = Console()


def _preflight() -> bool:
    """Return True if the target app is up, else print guidance."""
    from eval.deterministic import wait_until_vulnerable

    try:
        wait_until_vulnerable(BASE_URL, timeout_s=5.0)
        return True
    except RuntimeError:
        console.print(
            f"[red]Target app not reachable (or not vulnerable) at {BASE_URL}.[/red]\n"
            "Start it first: "
            "[cyan]uv run uvicorn target_app.app:app --reload --port 8001[/cyan]"
        )
        return False


def _run_deterministic(runs: int, rounds: int, timeout: int) -> None:
    from eval.deterministic import play_matches, reset_target, summarize
    from eval.reporting import render_deterministic, render_run_line

    console.print(f"[dim]Deterministic: playing {runs} match(es)...[/dim]")
    records = play_matches(runs, BASE_URL, rounds, timeout, on_run=render_run_line)
    console.print()
    render_deterministic(records, summarize(records))
    reset_target(BASE_URL)  # leave the app clean and vulnerable


def _run_behavioral() -> None:
    from eval.behavioral import run_behavioral
    from eval.deterministic import reset_target
    from eval.reporting import render_behavioral

    console.print("[dim]Behavioral: running Strands Evals (LLM judge)...[/dim]")
    report, judge_names = run_behavioral()
    render_behavioral(report, judge_names)
    reset_target(BASE_URL)  # leave the app clean and vulnerable for the next run


@click.command()
@click.option(
    "--mode",
    type=click.Choice(["deterministic", "behavioral", "both"]),
    default="deterministic",
    show_default=True,
    help="Which eval to run.",
)
@click.option(
    "--runs", default=5, show_default=True, help="Deterministic matches to play."
)
@click.option(
    "--rounds", default=MAX_ROUNDS, show_default=True, help="Max rounds per match."
)
@click.option(
    "--timeout",
    default=TIME_BUDGET_SECONDS,
    show_default=True,
    help="Time budget per match, in seconds.",
)
def main(mode: str, runs: int, rounds: int, timeout: int) -> None:
    """Evaluate the wargame: deterministic patch-rate, behavioral quality, or both."""
    if not _preflight():
        raise SystemExit(1)

    if mode in ("deterministic", "both"):
        _run_deterministic(runs, rounds, timeout)
    if mode in ("behavioral", "both"):
        if mode == "both":
            console.print()
        _run_behavioral()


if __name__ == "__main__":
    main()
