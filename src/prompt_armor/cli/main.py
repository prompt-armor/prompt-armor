"""CLI for prompt-armor.

Commands:
  analyze  Analyze a single prompt
  scan     Batch-scan prompt files in a directory
  config   Show resolved configuration
  version  Show version

Exit codes: 0=allow, 1=warn, 2=block, 3=error
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from prompt_armor._version import __version__
from prompt_armor.models import Decision

console = Console()

# Exit code mapping
_EXIT_CODES = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.BLOCK: 2,
    Decision.UNCERTAIN: 1,
}

_DECISION_COLORS = {
    Decision.ALLOW: "green",
    Decision.WARN: "yellow",
    Decision.BLOCK: "red",
    Decision.UNCERTAIN: "cyan",
}

_DECISION_ICONS = {
    Decision.ALLOW: "[green]✓ ALLOW[/green]",
    Decision.WARN: "[yellow]⚠ WARN[/yellow]",
    Decision.BLOCK: "[red]✗ BLOCK[/red]",
    Decision.UNCERTAIN: "[cyan]? UNCERTAIN[/cyan]",
}


def _score_bar(score: float, width: int = 20) -> str:
    """Create a visual score bar."""
    filled = int(score * width)
    empty = width - filled
    if score < 0.3:
        color = "green"
    elif score < 0.7:
        color = "yellow"
    else:
        color = "red"
    return f"[{color}]{'█' * filled}{'░' * empty}[/{color}] {score:.2f}"


def _result_to_dict(result: object) -> dict:
    """Convert ShieldResult to a JSON-serializable dict."""
    from prompt_armor.models import ShieldResult

    if not isinstance(result, ShieldResult):
        raise TypeError(f"Expected ShieldResult, got {type(result).__name__}")
    return result.to_dict()


@click.group()
@click.version_option(version=__version__, prog_name="prompt-armor")
def cli() -> None:
    """prompt-armor — LLM prompt security analysis."""


@cli.command()
@click.argument("prompt", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read prompt from file")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed layer results")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to config YAML")
def analyze(
    prompt: str | None,
    file: str | None,
    output_json: bool,
    verbose: bool,
    config: str | None,
) -> None:
    """Analyze a prompt for security risks.

    Exit codes: 0=allow, 1=warn, 2=block, 3=error
    """
    # Get the text to analyze
    if prompt is None and file is None:
        # Try to read from stdin
        if not sys.stdin.isatty():
            prompt = sys.stdin.read().strip()
        else:
            console.print("[red]Error:[/red] Provide a prompt as argument, --file, or pipe via stdin")
            sys.exit(3)

    if file is not None:
        prompt = Path(file).read_text().strip()

    if not prompt:
        console.print("[red]Error:[/red] Empty prompt")
        sys.exit(3)

    try:
        import logging
        import os
        import warnings

        # Suppress noisy model loading output
        os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
        warnings.filterwarnings("ignore", category=FutureWarning)
        logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
        logging.getLogger("transformers").setLevel(logging.ERROR)
        logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

        from prompt_armor.config import ShieldConfig, load_config
        from prompt_armor.engine import LiteEngine

        cfg = load_config(Path(config)) if config else ShieldConfig()
        engine = LiteEngine(cfg)
        result = engine.analyze(prompt)
        engine.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(3)

    if output_json:
        click.echo(json.dumps(_result_to_dict(result), indent=2))
    else:
        _print_rich_result(result, prompt, verbose)

    sys.exit(_EXIT_CODES.get(result.decision, 3))


@cli.command()
@click.option("--dir", "directory", required=True, type=click.Path(exists=True), help="Directory to scan")
@click.option("--glob", "pattern", default="*.txt", help="File glob pattern (default: *.txt)")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format",
)
@click.option("--fail-on", type=click.Choice(["warn", "block"]), default="block", help="Exit non-zero if any file reaches this level")
def scan(directory: str, pattern: str, fmt: str, fail_on: str) -> None:
    """Batch-scan prompt files in a directory."""
    from prompt_armor.engine import LiteEngine

    dir_path = Path(directory)
    files = sorted(dir_path.glob(pattern))

    if not files:
        console.print(f"[yellow]No files matching '{pattern}' in {directory}[/yellow]")
        sys.exit(0)

    engine = LiteEngine()
    results = []

    for filepath in files:
        text = filepath.read_text().strip()
        if not text:
            continue
        result = engine.analyze(text)
        results.append({"file": str(filepath.name), "result": result})

    engine.close()

    if fmt == "json":
        output = [
            {"file": r["file"], **_result_to_dict(r["result"])} for r in results
        ]
        click.echo(json.dumps(output, indent=2))
    elif fmt == "csv":
        click.echo("file,risk_score,confidence,decision,categories")
        for r in results:
            res = r["result"]
            cats = ";".join(c.value for c in res.categories)
            click.echo(f"{r['file']},{res.risk_score},{res.confidence},{res.decision.value},{cats}")
    else:
        _print_scan_table(results)

    # Determine exit code
    fail_threshold = Decision.WARN if fail_on == "warn" else Decision.BLOCK
    max_decision = max(
        (r["result"].decision for r in results),
        key=lambda d: list(_EXIT_CODES.keys()).index(d),
        default=Decision.ALLOW,
    )
    if _EXIT_CODES.get(max_decision, 0) >= _EXIT_CODES.get(fail_threshold, 2):
        sys.exit(_EXIT_CODES[max_decision])


@cli.command("config")
@click.option("--show", is_flag=True, default=True, help="Show resolved configuration")
@click.option("--init", is_flag=True, help="Create a template .prompt-armor.yml")
def config_cmd(show: bool, init: bool) -> None:
    """Show or initialize configuration."""
    if init:
        template = Path(".prompt-armor.yml")
        if template.exists():
            console.print("[yellow]Config file already exists[/yellow]")
            return
        template.write_text(
            "# prompt-armor configuration\n"
            "# See: https://github.com/prompt-armor/prompt-armor\n\n"
            "weights:\n"
            "  l1_regex: 0.20\n"
            "  l2_classifier: 0.30\n"
            "  l3_similarity: 0.30\n"
            "  l4_structural: 0.20\n\n"
            "thresholds:\n"
            "  allow_below: 0.3\n"
            "  block_above: 0.7\n"
            "  hard_block: 0.95\n"
            "  min_confidence: 0.5\n\n"
            "convergence_boost: 0.10\n"
            "divergence_penalty: 0.15\n"
        )
        console.print("[green]Created .prompt-armor.yml[/green]")
        return

    from prompt_armor.config import load_config

    cfg = load_config()
    console.print(Panel(cfg.model_dump_json(indent=2), title="Resolved Configuration"))


def _print_rich_result(result: object, prompt: str, verbose: bool) -> None:
    """Print analysis result with Rich formatting."""
    from prompt_armor.models import ShieldResult

    if not isinstance(result, ShieldResult):
        raise TypeError(f"Expected ShieldResult, got {type(result).__name__}")

    # Main panel
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Risk Score", _score_bar(result.risk_score))
    table.add_row("Confidence", f"{result.confidence:.2f}")
    table.add_row("Decision", _DECISION_ICONS[result.decision])
    if result.categories:
        cats = ", ".join(c.value for c in result.categories)
        table.add_row("Categories", cats)
    table.add_row("Latency", f"{result.latency_ms:.1f}ms")

    if result.needs_council:
        table.add_row("Council", "[cyan]Recommended (uncertainty detected)[/cyan]")

    console.print(Panel(table, title="prompt-armor analysis", border_style=_DECISION_COLORS[result.decision]))

    # Evidence
    if result.evidence:
        ev_table = Table(title="Evidence", show_lines=True)
        ev_table.add_column("Layer", style="cyan")
        ev_table.add_column("Category")
        ev_table.add_column("Description")
        ev_table.add_column("Score", justify="right")

        for ev in result.evidence:
            ev_table.add_row(ev.layer, ev.category.value, ev.description, f"{ev.score:.2f}")

        console.print(ev_table)

    # Verbose: layer details
    if verbose and result.layer_results:
        lr_table = Table(title="Layer Details", show_lines=True)
        lr_table.add_column("Layer", style="cyan")
        lr_table.add_column("Score", justify="right")
        lr_table.add_column("Confidence", justify="right")
        lr_table.add_column("Latency", justify="right")

        for lr in result.layer_results:
            lr_table.add_row(
                lr.layer,
                f"{lr.score:.4f}",
                f"{lr.confidence:.4f}",
                f"{lr.latency_ms:.2f}ms",
            )

        console.print(lr_table)


def _print_scan_table(results: list[dict]) -> None:
    """Print scan results as a Rich table."""
    from prompt_armor.models import ShieldResult

    table = Table(title="Scan Results", show_lines=True)
    table.add_column("File", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Decision")
    table.add_column("Categories")

    for r in results:
        res: ShieldResult = r["result"]
        color = _DECISION_COLORS[res.decision]
        cats = ", ".join(c.value for c in res.categories) or "-"
        table.add_row(
            r["file"],
            f"[{color}]{res.risk_score:.2f}[/{color}]",
            _DECISION_ICONS[res.decision],
            cats,
        )

    console.print(table)
