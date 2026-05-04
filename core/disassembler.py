"""
Disassembler for kernel binaries with IR normalization.

Converts raw binary code to intermediate representation by disassembling with Capstone
and applying normalization rules to create architecture-agnostic instruction fingerprints.
"""

from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64, Cs
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

from .loader import KernelImage
from .ir import IRFunction, IRInstruction

__all__ = ["Disassembler"]


class Disassembler:
    """
    Disassembles kernel binary code and produces normalized IR.

    Converts arch-specific assembly into a canonical representation suitable
    for fingerprinting and pattern matching across architectures.
    """

    # Mnemonic canonicalization: maps arch-specific forms to canonical names
    ARM64_MNEMONIC_MAP = {
        "ldr": "load",
        "ldp": "load",
        "str": "store",
        "stp": "store",
        "bl": "call",
        "blr": "call",
        "b": "jmp",
        "br": "jmp",
        "beq": "jmp_cond",
        "bne": "jmp_cond",
        "blt": "jmp_cond",
        "ble": "jmp_cond",
        "bgt": "jmp_cond",
        "bge": "jmp_cond",
        "ret": "ret",
        "add": "add",
        "sub": "sub",
        "mov": "mov",
        "movz": "mov",
        "movk": "mov",
    }

    X86_MNEMONIC_MAP = {
        "mov": "mov",
        "lea": "load_addr",
        "push": "push",
        "pop": "pop",
        "call": "call",
        "ret": "ret",
        "jmp": "jmp",
        "je": "jmp_cond",
        "jne": "jmp_cond",
        "jl": "jmp_cond",
        "jle": "jmp_cond",
        "jg": "jmp_cond",
        "jge": "jmp_cond",
        "add": "add",
        "sub": "sub",
        "xor": "xor",
        "and": "and",
        "or": "or",
        "cmp": "cmp",
        "test": "test",
        "endbr64": "endbr64",
    }

    def __init__(self, image: KernelImage) -> None:
        """
        Initialize a Disassembler.

        Args:
            image: KernelImage instance to disassemble
        """
        self.image = image
        self._setup_capstone()

    def _setup_capstone(self) -> None:
        """Configure Capstone disassembler for the target architecture."""
        if self.image.arch == "arm64":
            self.disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        elif self.image.arch == "x86_64":
            self.disasm = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            raise ValueError(f"Unsupported arch: {self.image.arch}")

    def disassemble_function(
        self, raw_bytes: bytes, base_addr: int = 0
    ) -> IRFunction:
        """
        Disassemble a function and return normalized IR.

        Args:
            raw_bytes: Raw binary code
            base_addr: Base address for disassembly (default 0)

        Returns:
            IRFunction with normalized instructions
        """
        instructions = []

        for instr in self.disasm.disasm(raw_bytes, base_addr):
            normalized = self._normalize_instruction(instr)
            instructions.append(normalized)

        return IRFunction(
            instructions=instructions,
            arch=self.image.arch,
            source_offset=base_addr,
        )

    def disassemble_range(self, offset: int, size: int) -> IRFunction:
        """
        Disassemble a range within the .text section.

        Args:
            offset: Byte offset within .text section
            size: Number of bytes to disassemble

        Returns:
            IRFunction with normalized instructions
        """
        end = min(offset + size, len(self.image.text_data))
        raw_bytes = self.image.text_data[offset:end]

        # base_addr is the absolute address (text_offset + relative offset)
        base_addr = self.image.text_offset + offset

        return self.disassemble_function(raw_bytes, base_addr)

    def _normalize_instruction(self, instr) -> IRInstruction:
        """
        Normalize a Capstone instruction to IR.

        Args:
            instr: Capstone Instruction object

        Returns:
            IRInstruction with canonical mnemonic and operand type tuple
        """
        # Canonicalize mnemonic
        mnemonic = self._canonicalize_mnemonic(instr.mnemonic)

        # Extract operand types
        op_types = self._extract_operand_types(instr)

        return IRInstruction(mnemonic=mnemonic, op_types=tuple(op_types))

    def _canonicalize_mnemonic(self, mnemonic: str) -> str:
        """
        Map architecture-specific mnemonics to canonical names.

        Args:
            mnemonic: Original Capstone mnemonic

        Returns:
            Canonical mnemonic string
        """
        if self.image.arch == "arm64":
            return self.ARM64_MNEMONIC_MAP.get(mnemonic, mnemonic)
        elif self.image.arch == "x86_64":
            return self.X86_MNEMONIC_MAP.get(mnemonic, mnemonic)
        return mnemonic

    def _extract_operand_types(self, instr) -> list[str]:
        """
        Extract operand type tokens from a Capstone instruction.

        Strips register names, immediate values, and addresses, replacing them
        with canonical type tokens: "REG", "IMM", "MEM", "LABEL".

        Args:
            instr: Capstone Instruction object

        Returns:
            List of operand type strings
        """
        op_types = []

        for operand in instr.operands:
            if self.image.arch == "arm64":
                op_type = self._arm64_operand_type(operand)
            elif self.image.arch == "x86_64":
                op_type = self._x86_operand_type(operand)
            else:
                op_type = "UNKNOWN"

            op_types.append(op_type)

        return op_types

    def _arm64_operand_type(self, operand) -> str:
        """Classify an ARM64 operand type."""
        if operand.type == ARM64_OP_REG:
            return "REG"
        elif operand.type == ARM64_OP_IMM:
            return "IMM"
        elif operand.type == ARM64_OP_MEM:
            return "MEM"
        else:
            return "UNKNOWN"

    def _x86_operand_type(self, operand) -> str:
        """Classify an x86_64 operand type."""
        if operand.type == X86_OP_REG:
            return "REG"
        elif operand.type == X86_OP_IMM:
            # Check if it's a branch label (LABEL operand)
            return "IMM"
        elif operand.type == X86_OP_MEM:
            return "MEM"
        else:
            return "UNKNOWN"