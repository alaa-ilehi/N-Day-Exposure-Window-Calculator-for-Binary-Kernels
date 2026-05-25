"""validation/test_ir.py — pytest tests for core.ir.IRNormalizer."""

from __future__ import annotations
import pytest
from core.ir import IRNormalizer


def _arm64() -> IRNormalizer:
    return IRNormalizer("arm64")


def _x86() -> IRNormalizer:
    return IRNormalizer("x86_64")


def test_normalize_arm64_empty() -> None:
    """Empty byte string returns an empty list without raising."""
    assert _arm64().normalize(b"") == []


def test_normalize_arm64_mov() -> None:
    """MOVZ X0, #0 (00 00 80 D2) -> mnemonic 'mov' or 'movz', op_class 'arith'."""
    result = _arm64().normalize(b"\x00\x00\x80\xd2")
    assert len(result) == 1
    # Capstone may canonicalize MOVZ X0,#0 to 'mov'
    assert result[0]["mnemonic"] in ("mov", "movz")
    assert result[0]["op_class"] == "arith"


def test_normalize_x86_ret() -> None:
    """x86_64 RET (0xC3) -> is_ret=True, op_class='ret'."""
    result = _x86().normalize(b"\xc3")
    assert len(result) == 1
    assert result[0]["is_ret"] is True
    assert result[0]["op_class"] == "ret"


def test_normalize_op_class_branch_arm64() -> None:
    """CBZ X0, #8 (40 00 00 B4) -> op_class='branch', is_branch=True."""
    result = _arm64().normalize(b"\x40\x00\x00\xb4")
    assert len(result) == 1
    assert result[0]["mnemonic"] == "cbz"
    assert result[0]["op_class"] == "branch"
    assert result[0]["is_branch"] is True


def test_normalize_returns_required_keys() -> None:
    """Each IR dict must contain all required keys."""
    required = {
        "mnemonic", "op_class", "writes_reg",
        "reads_mem", "writes_mem", "is_branch", "is_call", "is_ret",
    }
    # MOVZ X0,#0 then ARM64 RET
    result = _arm64().normalize(b"\x00\x00\x80\xd2" + b"\xc0\x03\x5f\xd6")
    assert isinstance(result, list)
    for ir in result:
        assert not (required - ir.keys()), f"Missing keys: {required - ir.keys()}"


def test_normalize_unsupported_arch_raises() -> None:
    """Unknown arch raises ValueError."""
    with pytest.raises(ValueError, match="Unsupported"):
        IRNormalizer("mips")


def test_normalize_x86_call_op_class() -> None:
    """x86_64 CALL rel32 (E8 00 00 00 00) -> op_class='call', is_call=True."""
    result = _x86().normalize(b"\xe8\x00\x00\x00\x00")
    assert len(result) >= 1
    assert result[0]["op_class"] == "call"
    assert result[0]["is_call"] is True
