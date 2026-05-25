"""
Intermediate representation for disassembled binary code.

Provides normalized, architecture-agnostic IR structures that capture the structural
shape of code without encoding specific register names or immediate values.
Also provides IRNormalizer for capstone-based disassembly into IR dicts.
"""

from dataclasses import dataclass
from typing import Optional

from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64, Cs

__all__ = ["IRInstruction", "IRFunction", "IRNormalizer"]

# ---------------------------------------------------------------------------
# Mnemonic classification sets
# ---------------------------------------------------------------------------
_ARM64_ARITH = {
    "add", "sub", "mul", "div", "neg", "asr", "lsl", "lsr", "ror",
    "mov", "movz", "movk", "movn",
}
_ARM64_LOGIC = {"and", "or", "orr", "xor", "eor", "eon", "bic", "not"}
_X86_ARITH   = {"add", "sub", "mul", "imul", "div", "idiv", "neg", "inc", "dec",
                "sar", "shl", "shr", "ror", "rol"}
_X86_LOGIC   = {"and", "or", "xor", "not", "test", "cmp"}


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


# ---------------------------------------------------------------------------
# IRNormalizer
# ---------------------------------------------------------------------------
class IRNormalizer:
    """Disassembles raw bytes with Capstone into normalized IR dicts (one per instruction)."""

    def __init__(self, arch: str) -> None:
        """Args: arch — 'arm64' or 'x86_64'."""
        self.arch = arch
        if arch == "arm64":
            self._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        elif arch == "x86_64":
            self._cs = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            raise ValueError(f"Unsupported architecture: {arch!r}")
        self._cs.detail = True

    def normalize(self, func_data: bytes, base_addr: int = 0) -> list[dict]:
        """Disassemble func_data and return normalized IR dicts. Undecodable bytes are skipped."""
        result: list[dict] = []
        for instr in self._cs.disasm(func_data, base_addr):
            try:
                result.append(self._classify(instr))
            except Exception:  # noqa: BLE001
                continue
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _classify(self, instr) -> dict:
        """Produce the normalized IR dict for one Capstone instruction."""
        mnem = instr.mnemonic.lower()
        op_class = self._op_class(mnem, instr)

        is_branch = op_class == "branch"
        is_call   = op_class == "call"
        is_ret    = op_class == "ret"

        writes_reg, reads_mem, writes_mem = self._operand_flags(mnem, instr)

        return {
            "mnemonic":  mnem,
            "op_class":  op_class,
            "writes_reg": writes_reg,
            "reads_mem":  reads_mem,
            "writes_mem": writes_mem,
            "is_branch":  is_branch,
            "is_call":    is_call,
            "is_ret":     is_ret,
        }

    def _op_class(self, mnem: str, instr) -> str:
        """Return the op_class string for *mnem*."""
        if self.arch == "arm64":
            if mnem.startswith("ldr") or mnem.startswith("ldp"):
                return "memory_load"
            if mnem.startswith("str") or mnem.startswith("stp"):
                return "memory_store"
            if mnem in ("bl", "blr"):
                return "call"
            if mnem in ("b", "br", "cbz", "cbnz", "tbz", "tbnz") or (
                mnem.startswith("b.") and len(mnem) > 2
            ):
                return "branch"
            if mnem == "ret":
                return "ret"
            if mnem in _ARM64_ARITH:
                return "arith"
            if mnem in _ARM64_LOGIC:
                return "logic"
            return "other"

        # x86_64
        try:
            from capstone.x86 import X86_OP_MEM
            has_mem = any(op.type == X86_OP_MEM for op in instr.operands)
        except Exception:
            has_mem = False

        if mnem in ("mov", "movs", "movzx", "movsx", "movsxd", "lea"):
            return "memory_load" if has_mem else "arith"
        if mnem == "call":
            return "call"
        if mnem in ("ret", "retn"):
            return "ret"
        if mnem == "jmp" or (mnem.startswith("j") and len(mnem) > 1):
            return "branch"
        if mnem in _X86_ARITH:
            return "arith"
        if mnem in _X86_LOGIC:
            return "logic"
        return "other"

    def _operand_flags(
        self, mnem: str, instr
    ) -> tuple[bool, bool, bool]:
        """Return (writes_reg, reads_mem, writes_mem) for one instruction."""
        writes_reg = False
        reads_mem  = False
        writes_mem = False

        if self.arch == "arm64":
            try:
                from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
                for idx, op in enumerate(instr.operands):
                    if op.type == ARM64_OP_MEM:
                        if mnem.startswith("ldr") or mnem.startswith("ldp"):
                            reads_mem = True
                        elif mnem.startswith("str") or mnem.startswith("stp"):
                            writes_mem = True
                    if op.type == ARM64_OP_REG and idx == 0:
                        if not (mnem.startswith("str") or mnem.startswith("stp")):
                            writes_reg = True
            except Exception:
                pass
        else:
            try:
                from capstone.x86 import X86_OP_MEM, X86_OP_REG
                for idx, op in enumerate(instr.operands):
                    if op.type == X86_OP_MEM:
                        if idx == 0:
                            writes_mem = True
                        else:
                            reads_mem = True
                    if op.type == X86_OP_REG and idx == 0:
                        writes_reg = True
            except Exception:
                pass

        return writes_reg, reads_mem, writes_mem
