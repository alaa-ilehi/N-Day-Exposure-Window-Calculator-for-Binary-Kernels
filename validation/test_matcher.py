"""validation/test_matcher.py — pytest tests for core.matcher.PatchMatcher."""

from __future__ import annotations
from pathlib import Path
import pytest
from core.ir import IRFunction, IRInstruction
from core.matcher import PatchMatcher, MatchResult

FINGERPRINTS_DIR = Path(__file__).parent.parent / "fingerprints"


def _matcher() -> PatchMatcher:
    return PatchMatcher(FINGERPRINTS_DIR)


def _fn(instructions: list[IRInstruction], arch: str = "arm64") -> IRFunction:
    return IRFunction(instructions=instructions, arch=arch, source_offset=0)


def test_load_fingerprints() -> None:
    """Three CVE YAML files -> fingerprints list has exactly 3 entries."""
    assert len(_matcher().fingerprints) == 3


def test_match_empty_ir() -> None:
    """Empty IRFunction returns None (no CVE exceeds confidence threshold)."""
    assert _matcher().match(_fn([])) is None


def test_score_perfect_match() -> None:
    """IRFunction identical to CVE-2022-20421 post_patch -> confidence >= 0.9, verdict patched."""
    post_patch = [
        IRInstruction(mnemonic="load",    op_types=("REG", "MEM")),
        IRInstruction(mnemonic="cmp",     op_types=("REG", "IMM")),
        IRInstruction(mnemonic="branch",  op_types=("LABEL",)),
        IRInstruction(mnemonic="load",    op_types=("REG", "MEM")),
        IRInstruction(mnemonic="ref_inc", op_types=("MEM",)),
        IRInstruction(mnemonic="call",    op_types=("LABEL",)),
        IRInstruction(mnemonic="store",   op_types=("MEM", "REG")),
        IRInstruction(mnemonic="load",    op_types=("REG", "MEM")),
        IRInstruction(mnemonic="add",     op_types=("REG", "REG", "IMM")),
        IRInstruction(mnemonic="store",   op_types=("MEM", "REG")),
        IRInstruction(mnemonic="ret",     op_types=()),
    ]
    result = _matcher().match(_fn(post_patch))
    assert result is not None
    assert isinstance(result, MatchResult)
    assert result.confidence >= 0.9
    assert result.cve == "CVE-2022-20421"
    assert result.verdict == "patched"


def test_score_no_match() -> None:
    """All-ret function has score < 0.5 -> matcher returns None."""
    ret_only = [IRInstruction(mnemonic="ret", op_types=()) for _ in range(8)]
    assert _matcher().match(_fn(ret_only)) is None


def test_match_result_is_single_object() -> None:
    """match() returns None or a single MatchResult, never a list."""
    fn = _fn([
        IRInstruction(mnemonic="load",   op_types=("REG", "MEM")),
        IRInstruction(mnemonic="cmp",    op_types=("REG", "IMM")),
        IRInstruction(mnemonic="branch", op_types=("LABEL",)),
        IRInstruction(mnemonic="call",   op_types=("LABEL",)),
        IRInstruction(mnemonic="store",  op_types=("MEM", "REG")),
        IRInstruction(mnemonic="ret",    op_types=()),
    ])
    result = _matcher().match(fn)
    assert result is None or isinstance(result, MatchResult)


def test_missing_fingerprints_dir() -> None:
    """Missing fingerprints directory -> empty list or FileNotFoundError, not a crash."""
    try:
        m = PatchMatcher(Path("/nonexistent_xyz_404"))
        assert len(m.fingerprints) == 0
    except (FileNotFoundError, OSError):
        pass
