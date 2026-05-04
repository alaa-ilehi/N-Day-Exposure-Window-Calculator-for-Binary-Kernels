"""
Intermediate representation for disassembled binary code.

Provides normalized, architecture-agnostic IR structures that capture the structural
shape of code without encoding specific register names or immediate values.
"""

from dataclasses import dataclass

__all__ = ["IRInstruction", "IRFunction"]


@dataclass(frozen=True)
class IRInstruction:
    """
    Normalized instruction representation.

    Operands are represented by type tokens only, not actual values or register names.
    This allows architecture-agnostic fingerprinting of binary code.

    Attributes:
        mnemonic: Canonical operation name (e.g., "load", "store", "call", "ret")
        op_types: Tuple of operand type tokens: "REG", "IMM", "MEM", "LABEL"
    """

    mnemonic: str
    op_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class IRFunction:
    """
    Intermediate representation of a disassembled function.

    Attributes:
        instructions: List of normalized IR instructions
        arch: Source CPU architecture ("arm64" or "x86_64")
        source_offset: File offset where this function begins in the binary
    """

    instructions: list[IRInstruction]
    arch: str
    source_offset: int
