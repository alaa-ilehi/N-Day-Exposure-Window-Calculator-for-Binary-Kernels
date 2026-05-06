"""
cli.py — Patch Shadow command-line interface.

Entry point: `poetry run patch-shadow`
Commands   : scan, list-cves
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import print as rprint

# ---------------------------------------------------------------------------
# Lazy imports of core — keeps startup fast and gives clean error messages
# when a dependency (e.g. capstone) is missing.
# ---------------------------------------------------------------------------
def _import_core():
    from core.loader import KernelImage
    from core.function_detector import FunctionDetector
    from core.disassembler import Disassembler
    from core.matcher import PatchMatcher
    from core.exposure import ExposureCalculator
    return KernelImage, FunctionDetector, Disassembler, PatchMatcher, ExposureCalculator


# ---------------------------------------------------------------------------
# Rich console — stderr for status, stdout for machine-readable output
# ---------------------------------------------------------------------------
console = Console(stderr=False)
err_console = Console(stderr=True)

app = typer.Typer(
    name="patch-shadow",
    help="Patch presence verification for N-day kernel vulnerabilities in vendor binaries.",
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,
)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = r"""
 ██████╗  █████╗ ████████╗ ██████╗██╗  ██╗    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
 ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
 ██████╔╝███████║   ██║   ██║     ███████║    ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
 ██╔═══╝ ██╔══██║   ██║   ██║     ██╔══██║    ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
 ██║     ██║  ██║   ██║   ╚██████╗██║  ██║    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
 ╚═╝     ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
"""

TAGLINE = "⬡  Binary-level CVE patch verification for stripped OEM kernels  ⬡"
VERSION = "0.1.0"


def _print_banner() -> None:
    """Print the full Patch Shadow banner with metadata row."""
    console.print()
    banner_text = Text(BANNER, style="bold cyan")
    console.print(banner_text, justify="left")

    meta = Table.grid(padding=(0, 4))
    meta.add_row(
        Text("◈ version", style="dim cyan"),
        Text(VERSION, style="bold white"),
        Text("◈ arch", style="dim cyan"),
        Text("arm64 / x86_64", style="bold white"),
        Text("◈ cves", style="dim cyan"),
        Text("CVE-2022-20421  CVE-2023-0266  CVE-2022-2588", style="bold white"),
    )
    console.print(meta, justify="center")
    console.print()
    console.print(f"[dim]{TAGLINE}[/dim]", justify="center")
    console.print()
    console.print(Rule(style="cyan dim"))
    console.print()


# ---------------------------------------------------------------------------
# Verdict colours & symbols
# ---------------------------------------------------------------------------
VERDICT_STYLE = {
    "patched":       ("bold green",  "✔"),
    "vulnerable":    ("bold red",    "✘"),
    "inconclusive":  ("bold yellow", "◌"),
}

RISK_STYLE = {
    "critical": ("bold red",          "💀 CRITICAL"),
    "high":     ("bold red",          "⚠  HIGH"),
    "medium":   ("bold yellow",       "◆  MEDIUM"),
    "low":      ("bold yellow",       "◇  LOW"),
    "clean":    ("bold green",        "✔  CLEAN"),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _load_fingerprints_dir(fingerprints: Path) -> Path:
    if not fingerprints.exists():
        err_console.print(
            f"[bold red]✘  Fingerprints directory not found:[/bold red] {fingerprints}\n"
            "   Pass [cyan]--fingerprints <path>[/cyan] or run from the project root."
        )
        raise typer.Exit(code=2)
    yamls = list(fingerprints.glob("*.yaml")) + list(fingerprints.glob("*.yml"))
    if not yamls:
        err_console.print(
            f"[bold yellow]⚠  No YAML fingerprint files found in:[/bold yellow] {fingerprints}\n"
            "   The scan will produce no results."
        )
    return fingerprints


def _build_results_table(results: list, summary) -> Table:
    """Build the Rich results table from a list of MatchResult objects."""
    tbl = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan dim",
        padding=(0, 2),
        expand=False,
    )
    tbl.add_column("CVE",        style="bold white",  no_wrap=True, min_width=18)
    tbl.add_column("Verdict",    no_wrap=True,        min_width=14)
    tbl.add_column("Pre-score",  justify="right",     min_width=10)
    tbl.add_column("Post-score", justify="right",     min_width=10)
    tbl.add_column("Confidence", justify="right",     min_width=10)

    for r in results:
        style, symbol = VERDICT_STYLE.get(r.verdict, ("white", "?"))
        tbl.add_row(
            r.cve,
            Text(f"{symbol}  {r.verdict}", style=style),
            f"{r.pre_score:.3f}",
            f"{r.post_score:.3f}",
            Text(f"{r.confidence:.3f}", style=style),
        )

    return tbl


def _build_summary_panel(summary) -> Panel:
    """Build the exposure summary panel."""
    risk_style, risk_label = RISK_STYLE.get(summary.risk_level, ("white", summary.risk_level.upper()))

    grid = Table.grid(padding=(0, 3))
    grid.add_row(
        Text("RISK LEVEL",      style="dim"),
        Text(risk_label,        style=risk_style),
    )
    grid.add_row(
        Text("EXPOSURE SCORE",  style="dim"),
        Text(f"{summary.exposure_score:.2f}", style="bold white"),
    )
    grid.add_row(
        Text("TOTAL CHECKED",   style="dim"),
        Text(str(summary.total_checked), style="bold white"),
    )
    if summary.vulnerable:
        grid.add_row(
            Text("VULNERABLE",  style="dim red"),
            Text("  ".join(summary.vulnerable), style="bold red"),
        )
    if summary.patched:
        grid.add_row(
            Text("PATCHED",     style="dim green"),
            Text("  ".join(summary.patched), style="bold green"),
        )
    if summary.inconclusive:
        grid.add_row(
            Text("INCONCLUSIVE",style="dim yellow"),
            Text("  ".join(summary.inconclusive), style="bold yellow"),
        )

    return Panel(
        grid,
        title="[bold cyan]◈  Exposure Summary[/bold cyan]",
        border_style="cyan",
        padding=(1, 3),
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context):
    """Show banner when invoked with no sub-command."""
    if ctx.invoked_subcommand is None:
        _print_banner()
        console.print("[dim]Run[/dim] [cyan]patch-shadow --help[/cyan] [dim]for usage.[/dim]\n")


@app.command(name="scan")
def scan(
    binary_path: Path = typer.Argument(
        ...,
        help="Path to the stripped kernel binary (ELF).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: str = typer.Option(
        "table",
        "--output", "-o",
        help="Output format: [cyan]table[/cyan] or [cyan]json[/cyan].",
        show_default=True,
    ),
    fingerprints: Path = typer.Option(
        Path("fingerprints"),
        "--fingerprints", "-f",
        help="Directory containing CVE YAML fingerprint files.",
        show_default=True,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Suppress banner and progress output.",
    ),
):
    """
    [bold cyan]◈  Scan[/bold cyan] a kernel binary for known unpatched CVEs.

    Extracts functions from the binary, normalises disassembly into an
    arch-agnostic IR, and matches against pre/post-patch signatures.

    [dim]Examples:[/dim]

      [cyan]patch-shadow scan kernel.bin[/cyan]
      [cyan]patch-shadow scan kernel.bin --output json[/cyan]
      [cyan]patch-shadow scan kernel.bin --fingerprints ./my-fps[/cyan]
    """
    if not quiet:
        _print_banner()

    if output not in ("table", "json"):
        err_console.print("[bold red]✘  --output must be 'table' or 'json'.[/bold red]")
        raise typer.Exit(code=1)

    fp_dir = _load_fingerprints_dir(fingerprints)

    # ── Import core ────────────────────────────────────────────────────────
    try:
        KernelImage, FunctionDetector, Disassembler, PatchMatcher, ExposureCalculator = _import_core()
    except ImportError as exc:
        err_console.print(f"[bold red]✘  Failed to import core modules:[/bold red] {exc}")
        err_console.print("   Run [cyan]poetry install[/cyan] to install dependencies.")
        raise typer.Exit(code=3)

    # ── Load binary ────────────────────────────────────────────────────────
    if not quiet:
        console.print(f"[cyan]◈[/cyan]  Loading binary  [dim]{binary_path}[/dim]")

    try:
        from core.exceptions import NotAnELFError, UnsupportedArchError
        image = KernelImage.from_file(binary_path)
    except NotAnELFError:
        err_console.print(
            f"[bold red]✘  Not a valid ELF file:[/bold red] {binary_path}"
        )
        raise typer.Exit(code=1)
    except UnsupportedArchError as exc:
        err_console.print(
            f"[bold red]✘  Unsupported architecture:[/bold red] {exc}\n"
            "   Patch Shadow supports [cyan]arm64[/cyan] and [cyan]x86_64[/cyan] only."
        )
        raise typer.Exit(code=2)
    except FileNotFoundError:
        err_console.print(f"[bold red]✘  File not found:[/bold red] {binary_path}")
        raise typer.Exit(code=1)

    if not quiet:
        console.print(f"[cyan]◈[/cyan]  Architecture    [bold white]{image.arch}[/bold white]")
        console.print(f"[cyan]◈[/cyan]  .text size      [bold white]{len(image.text_data):,} bytes[/bold white]")

    # ── Detect functions ───────────────────────────────────────────────────
    if not quiet:
        console.print(f"[cyan]◈[/cyan]  Detecting function boundaries …")

    detector   = FunctionDetector(image)
    boundaries = detector.detect()

    if not quiet:
        console.print(f"[cyan]◈[/cyan]  Found [bold white]{len(boundaries)}[/bold white] candidate functions")

    # ── Disassemble + match ────────────────────────────────────────────────
    disassembler = Disassembler(image)
    matcher      = PatchMatcher(fp_dir)

    if not quiet:
        console.print(f"[cyan]◈[/cyan]  Scanning against [bold white]{len(matcher.fingerprints)}[/bold white] CVE fingerprint(s) …\n")

    results = []
    for boundary in boundaries:
        try:
            ir_fn  = disassembler.disassemble_range(boundary.start_offset, boundary.size)
            result = matcher.match(ir_fn)
            if result is not None:
                results.append(result)
        except Exception:
            # Heuristic detection will produce un-disassemblable ranges; skip silently.
            continue

    # ── Deduplicate: keep highest-confidence result per CVE ────────────────
    best: dict[str, object] = {}
    for r in results:
        if r.cve not in best or r.confidence > best[r.cve].confidence:
            best[r.cve] = r
    results = list(best.values())

    # ── Exposure summary ───────────────────────────────────────────────────
    calculator = ExposureCalculator(results)
    summary    = calculator.summary()

    # ── Render output ──────────────────────────────────────────────────────
    if output == "json":
        out = {
            "binary": str(binary_path),
            "arch":   image.arch,
            "total_checked":   summary.total_checked,
            "exposure_score":  round(summary.exposure_score, 4),
            "risk_level":      summary.risk_level,
            "vulnerable":      summary.vulnerable,
            "patched":         summary.patched,
            "inconclusive":    summary.inconclusive,
            "results": [
                {
                    "cve":        r.cve,
                    "verdict":    r.verdict,
                    "pre_score":  round(r.pre_score,  4),
                    "post_score": round(r.post_score, 4),
                    "confidence": round(r.confidence, 4),
                }
                for r in results
            ],
        }
        print(json.dumps(out, indent=2))
        return

    # table output
    if not results:
        console.print("[bold yellow]⚠  No CVE matches found.[/bold yellow]")
        console.print("[dim]   Try lowering confidence thresholds in the YAML fingerprints.[/dim]\n")
        return

    console.print(_build_results_table(results, summary))
    console.print()
    console.print(_build_summary_panel(summary))
    console.print()


@app.command(name="list-cves")
def list_cves(
    fingerprints: Path = typer.Option(
        Path("fingerprints"),
        "--fingerprints", "-f",
        help="Directory containing CVE YAML fingerprint files.",
        show_default=True,
    ),
):
    """
    [bold cyan]◈  List[/bold cyan] all CVE fingerprints that Patch Shadow knows about.
    """
    _print_banner()

    fp_dir = _load_fingerprints_dir(fingerprints)

    import yaml  # pyyaml — already in pyproject.toml

    yamls = sorted(fp_dir.glob("*.yaml")) + sorted(fp_dir.glob("*.yml"))
    if not yamls:
        console.print("[bold yellow]⚠  No fingerprint files found.[/bold yellow]")
        raise typer.Exit()

    tbl = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan dim",
        padding=(0, 2),
    )
    tbl.add_column("CVE",         style="bold white", no_wrap=True, min_width=18)
    tbl.add_column("CVSS",        justify="center",   min_width=6)
    tbl.add_column("Subsystem",   min_width=16)
    tbl.add_column("Function",    min_width=24)
    tbl.add_column("Description", min_width=40)

    for fp in yamls:
        with open(fp, "r") as fh:
            data = yaml.safe_load(fh) or {}
        cvss_val = str(data.get("cvss", "—"))
        cvss_style = (
            "bold red"    if float(cvss_val) >= 7.0 else
            "bold yellow" if float(cvss_val) >= 4.0 else
            "bold green"
        ) if cvss_val != "—" else "dim"
        tbl.add_row(
            data.get("cve", fp.stem),
            Text(cvss_val, style=cvss_style),
            data.get("subsystem", "—"),
            data.get("affected_function", "—"),
            data.get("description", "—"),
        )

    console.print(tbl)
    console.print(f"\n[dim]  {len(yamls)} fingerprint(s) loaded from[/dim] [cyan]{fp_dir}[/cyan]\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    app()


if __name__ == "__main__":
    main()