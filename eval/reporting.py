from rich.console import Console
from rich.table import Table

from game_controller import KNOWN_VULNERABILITIES
from eval.deterministic import DeterministicSummary, RunRecord

console = Console()


def render_run_line(record: RunRecord) -> None:
    """One progress line as each deterministic match finishes."""
    full = len(record.patched) == record.total
    colour = "green" if full else "yellow"
    console.print(
        f"  Run {record.index}: [{colour}]{len(record.patched)}/{record.total}[/] "
        f"patched in {record.rounds} round(s), {record.elapsed_s:.0f}s"
    )


def render_deterministic(
    records: list[RunRecord], summary: DeterministicSummary
) -> None:
    """Per-run table, aggregate metrics, and per-vulnerability breakdown."""
    runs = Table(title="Deterministic — runs", show_header=True, header_style="bold")
    runs.add_column("#", justify="right")
    runs.add_column("patched", justify="right")
    runs.add_column("rounds", justify="right")
    runs.add_column("time", justify="right")
    runs.add_column("stop reason")
    for r in records:
        full = len(r.patched) == r.total
        runs.add_row(
            str(r.index),
            f"[{'green' if full else 'yellow'}]{len(r.patched)}/{r.total}[/]",
            str(r.rounds),
            f"{r.elapsed_s:.0f}s",
            r.stop_reason or "-",
        )
    console.print(runs)

    n = summary.runs or 1
    metrics = Table(title="Deterministic — aggregate", show_header=False)
    metrics.add_column("metric", style="bold")
    metrics.add_column("value")
    metrics.add_row("runs", str(summary.runs))
    metrics.add_row(
        "full-sweep rate",
        f"{summary.full_sweeps}/{summary.runs} ({summary.full_sweeps / n:.0%})",
    )
    metrics.add_row("avg patched", f"{summary.avg_patched:.2f}/{summary.total}")
    metrics.add_row("patch rate", f"{summary.avg_patched / summary.total:.0%}")
    metrics.add_row(
        "avg rounds to full sweep",
        (
            f"{summary.avg_sweep_rounds:.1f}"
            if summary.avg_sweep_rounds is not None
            else "n/a"
        ),
    )
    console.print(metrics)

    breakdown = Table(
        title="Deterministic — per vulnerability", show_header=True, header_style="bold"
    )
    breakdown.add_column("vulnerability")
    breakdown.add_column("fixed in", justify="right")
    for vuln in KNOWN_VULNERABILITIES:
        fixed = summary.per_vuln_fixed.get(vuln.id, 0)
        colour = "green" if fixed == summary.runs else "yellow" if fixed else "red"
        breakdown.add_row(vuln.id, f"[{colour}]{fixed}/{summary.runs}[/]")
    console.print(breakdown)


def render_behavioral(report, evaluator_names: list[str] | None = None) -> None:
    """Render the Strands Evals report: its own summary, plus each judge's full reason."""
    console.rule("[bold]Behavioral — Strands Evals[/bold]")
    try:
        report.display()
    except Exception:
        console.print(report)

    overall = getattr(report, "overall_score", None)
    if overall is not None:
        console.print(f"\n[bold]Overall score:[/bold] {overall:.2f}")

    # The SDK table truncates reasons; print them in full. detailed_results is
    # [per case][per evaluator], so the inner index matches the evaluator order.
    names = evaluator_names or []
    detailed = getattr(report, "detailed_results", None) or []
    for case_outputs in detailed:
        for i, out in enumerate(case_outputs):
            name = names[i] if i < len(names) else f"judge {i + 1}"
            score = getattr(out, "score", None)
            passed = getattr(out, "test_pass", None)
            reason = getattr(out, "reason", "") or ""
            mark = "PASS" if passed else "FAIL"
            colour = "green" if passed else "red"
            header = f"[bold]{name}[/bold]"
            if isinstance(score, (int, float)):
                header += f" — {score:.2f} [{colour}]{mark}[/]"
            console.print()
            console.print(header)
            if reason:
                console.print(reason)
