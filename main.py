import click
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from game_controller import (
    KNOWN_VULNERABILITIES,
    MAX_ROUNDS,
    TIME_BUDGET_SECONDS,
    run_game,
)

console = Console()

STOP_REASON_TEXT = {
    "all_patched": "All vulnerabilities patched",
    "max_rounds": "Reached the round limit",
    "timeout": "Hit the time budget",
    "incomplete": "Round did not finish — scored the app as-is",
}


def preflight(target: str) -> bool:
    """Return True if the target app answers, else print guidance and return False."""
    try:
        httpx.get(f"{target}/", timeout=5)
        return True
    except httpx.HTTPError:
        console.print(
            Panel(
                f"Could not reach the target app at [bold]{target}[/bold].\n\n"
                "Start it first, in another terminal:\n"
                "  [cyan]uv run uvicorn target_app.app:app --reload --port 8001[/cyan]",
                title="[red]Target not reachable[/red]",
                border_style="red",
            )
        )
        return False


def render_round(event: dict) -> None:
    """Print one colour-coded line per round, called by the controller after scoring."""
    patched = ", ".join(event["patched"]) if event["patched"] else "none"
    console.print(
        f"[bold]Round {event['round']:>2}/{MAX_ROUNDS}[/bold]  "
        f"patched: [green]{patched}[/green]  "
        f"([green]{len(event['patched'])}[/green]/{event['total']})  "
        f"[dim]{event['elapsed_s']:.0f}s[/dim]"
    )


def render_summary(result) -> None:
    """Print the final scoreboard panel."""
    patched = set(result.patched)
    table = Table(show_header=True, header_style="bold")
    table.add_column("Vulnerability")
    table.add_column("Status")
    for vuln in KNOWN_VULNERABILITIES:
        if vuln.id in patched:
            table.add_row(vuln.id, "[green]patched[/green]")
        else:
            table.add_row(vuln.id, "[red]OPEN[/red]")

    reason = STOP_REASON_TEXT.get(result.stop_reason) or "Did not finish a scored round"
    console.print()
    console.print(
        Panel(
            table,
            title=f"[bold]Match over — {reason}[/bold]",
            subtitle=f"{len(patched)}/{result.total} patched in {result.rounds} round(s)",
            border_style="green" if len(patched) == result.total else "yellow",
        )
    )


@click.command()
@click.option("--target", default="http://localhost:8001", help="Target app base URL.")
@click.option("--rounds", default=MAX_ROUNDS, show_default=True, help="Maximum rounds.")
@click.option(
    "--timeout",
    default=TIME_BUDGET_SECONDS,
    show_default=True,
    help="Time budget in seconds.",
)
def main(target: str, rounds: int, timeout: int) -> None:
    """Run a Red Team vs Blue Team security wargame against the target app."""
    console.print(
        Panel(
            f"Target: [bold]{target}[/bold]   Rounds: {rounds}   Timeout: {timeout}s",
            title="[bold red]Red[/bold red] vs [bold blue]Blue[/bold blue] Wargame",
            border_style="magenta",
        )
    )

    if not preflight(target):
        raise SystemExit(1)

    console.print(
        "[dim]Starting match. Red attacks, Blue defends, scored each round...[/dim]\n"
    )
    result = run_game(
        base_url=target,
        max_rounds=rounds,
        time_budget_s=timeout,
        on_event=render_round,
    )
    render_summary(result)


if __name__ == "__main__":
    main()
