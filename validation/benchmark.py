from __future__ import annotations

import csv
import sys
import time
from pathlib import Path
from typing import NamedTuple

import typer
from rich import box
from rich.console import Console
from rich.table import Table

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent
DEFAULT_CSV = REPO_ROOT / "validation" / "ground_truth.csv"
DEFAULT_FP  = REPO_ROOT / "fingerprints"

console = Console()
app     = typer.Typer(add_completion=False)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------
class GroundTruthRow(NamedTuple):
    binary_path: Path
    cve: str
    expected_verdict: str
    notes: str


class BenchmarkResult(NamedTuple):
    binary_path: Path
    cve: str
    expected: str
    got: str          # "patched" | "vulnerable" | "inconclusive" | "not_found"
    confidence: float
    elapsed_s: float
    correct: bool


# ---------------------------------------------------------------------------
# CSV loader
# ---------------------------------------------------------------------------
def load_ground_truth(csv_path: Path) -> list[GroundTruthRow]:
    """Load non-comment rows from the ground-truth CSV."""
    rows: list[GroundTruthRow] = []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(
            (line for line in fh if not line.lstrip().startswith("#"))
        )
        for r in reader:
            path = Path(r["binary_path"].strip())
            rows.append(GroundTruthRow(
                binary_path=path,
                cve=r["cve"].strip(),
                expected_verdict=r["expected_verdict"].strip(),
                notes=r.get("notes", "").strip(),
            ))
    return rows


# ---------------------------------------------------------------------------
# Single-binary scan
# ---------------------------------------------------------------------------
def _scan_one(binary: Path, cve: str, fp_dir: Path) -> tuple[str, float]:
    """Return (verdict, confidence) for one binary+CVE pair."""
    try:
        from core.loader import KernelImage
        from core.function_detector import FunctionDetector
        from core.disassembler import Disassembler
        from core.matcher import PatchMatcher
        from core.exceptions import NotAnELFError, UnsupportedArchError
    except ImportError as exc:
        console.print(f"[red]Import error:[/red] {exc}")
        return "error", 0.0

    try:
        image = KernelImage.from_file(binary)
    except (NotAnELFError, UnsupportedArchError, FileNotFoundError) as exc:
        return f"error:{exc}", 0.0

    detector     = FunctionDetector(image)
    disassembler = Disassembler(image)
    matcher      = PatchMatcher(fp_dir)

    best_verdict    = "not_found"
    best_confidence = 0.0

    for boundary in detector.detect():
        try:
            ir_fn  = disassembler.disassemble_range(boundary.start_offset, boundary.size)
            result = matcher.match(ir_fn)
            if result is None or result.cve != cve:
                continue
            if result.confidence > best_confidence:
                best_confidence = result.confidence
                best_verdict    = result.verdict
        except Exception:
            continue

    return best_verdict, best_confidence


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def _compute_metrics(results: list[BenchmarkResult]) -> dict:
    total   = len(results)
    correct = sum(1 for r in results if r.correct)
    not_found = sum(1 for r in results if r.got == "not_found")

    # Per-CVE accuracy
    per_cve: dict[str, dict] = {}
    for r in results:
        entry = per_cve.setdefault(r.cve, {"total": 0, "correct": 0})
        entry["total"] += 1
        if r.correct:
            entry["correct"] += 1

    return {
        "total":     total,
        "correct":   correct,
        "accuracy":  correct / total if total else 0.0,
        "not_found": not_found,
        "per_cve":   per_cve,
    }


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------
@app.command()
def run(
    csv_path: Path = typer.Option(DEFAULT_CSV, "--csv",          help="Ground-truth CSV file."),
    fp_dir:   Path = typer.Option(DEFAULT_FP,  "--fingerprints", help="Fingerprints directory."),
):
    """Run the Patch Shadow accuracy benchmark against labelled kernel binaries."""
    if not csv_path.exists():
        console.print(f"[red]CSV not found:[/red] {csv_path}")
        raise typer.Exit(1)

    rows = load_ground_truth(csv_path)
    if not rows:
        console.print("[yellow]No ground-truth rows found (all lines are comments).[/yellow]")
        raise typer.Exit(0)

    console.print(f"Loaded [bold]{len(rows)}[/bold] ground-truth entries. Scanning...\n")

    results: list[BenchmarkResult] = []
    for row in rows:
        t0 = time.perf_counter()
        verdict, conf = _scan_one(row.binary_path, row.cve, fp_dir)
        elapsed = time.perf_counter() - t0

        correct = verdict == row.expected_verdict
        results.append(BenchmarkResult(
            binary_path=row.binary_path,
            cve=row.cve,
            expected=row.expected_verdict,
            got=verdict,
            confidence=conf,
            elapsed_s=elapsed,
            correct=correct,
        ))
        status = "[green]OK[/green]" if correct else "[red]FAIL[/red]"
        console.print(f"  {status}  {row.binary_path.name:<30} {row.cve:<20} "
                      f"expected={row.expected_verdict:<12} got={verdict:<12} conf={conf:.3f}")

    metrics = _compute_metrics(results)

    # Results table
    tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    tbl.add_column("CVE",      min_width=20)
    tbl.add_column("Samples",  justify="right", min_width=8)
    tbl.add_column("Correct",  justify="right", min_width=8)
    tbl.add_column("Accuracy", justify="right", min_width=10)

    for cve, m in sorted(metrics["per_cve"].items()):
        acc = m["correct"] / m["total"] if m["total"] else 0.0
        tbl.add_row(cve, str(m["total"]), str(m["correct"]), f"{acc:.1%}")

    console.print()
    console.print(tbl)
    console.print(
        f"\nOverall accuracy: [bold]{metrics['accuracy']:.1%}[/bold]  "
        f"({metrics['correct']}/{metrics['total']} correct, "
        f"{metrics['not_found']} not matched)\n"
    )

    sys.exit(0 if metrics["accuracy"] >= 0.80 else 1)


if __name__ == "__main__":
    app()
