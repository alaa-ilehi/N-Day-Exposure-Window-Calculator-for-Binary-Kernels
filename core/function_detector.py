"""
Function boundary detection in stripped kernel binaries.

Uses heuristic prologue/epilogue pattern matching on disassembled code to identify
function boundaries without relying on symbol tables.
"""

from collections import namedtuple
from typing import NamedTuple

from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64, Cs

from .loader import KernelImage

__all__ = ["FunctionBoundary", "FunctionDetector"]


class FunctionBoundary(NamedTuple):
    """
    Represents the boundary of a detected function.

    Attributes:
        start_offset: Byte offset in .text section where function begins
        end_offset: Estimated byte offset where function ends (exclusive)
        size: Size in bytes (end_offset - start_offset)
    """

    start_offset: int
    end_offset: int
    size: int


class FunctionDetector:
    """
    Detects function boundaries in stripped kernel binaries using prologue heuristics.

    Supports ARM64 and x86_64 architectures. Ignores functions smaller than 32 bytes
    or larger than 8192 bytes to filter out inline stubs and outliers.
    """

    # Size limits for detected functions (bytes)
    MIN_FUNC_SIZE = 32
    MAX_FUNC_SIZE = 8192

    def __init__(self, image: KernelImage) -> None:
        """
        Initialize a FunctionDetector.

        Args:
            image: KernelImage instance containing the binary to analyze
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

    def detect(self) -> list[FunctionBoundary]:
        """
        Detect function boundaries in the .text section.

        Uses prologue pattern matching to identify function starts and end offsets.
        Returns only functions within the valid size range.

        Returns:
            List of FunctionBoundary instances sorted by start_offset
        """
        boundaries = []
        prologue_offsets = self._find_prologue_offsets()

        if not prologue_offsets:
            return []

        for i, start in enumerate(prologue_offsets):
            # End offset is the start of the next prologue or end of text
            end = (
                prologue_offsets[i + 1]
                if i + 1 < len(prologue_offsets)
                else len(self.image.text_data)
            )

            size = end - start
            if self.MIN_FUNC_SIZE <= size <= self.MAX_FUNC_SIZE:
                boundaries.append(
                    FunctionBoundary(
                        start_offset=start,
                        end_offset=end,
                        size=size,
                    )
                )

        return boundaries

    def _find_prologue_offsets(self) -> list[int]:
        """
        Find offsets of likely function prologues.

        ARM64 patterns:
        - stp x29, x30, [sp, #-N]!  (push rbp+lrr with pre-increment)
        - sub sp, sp, #N             (stack allocation)

        x86_64 patterns:
        - push rbp; mov rbp, rsp    (frame pointer setup)
        - endbr64                    (CET marker)

        Returns:
            Sorted list of prologue offsets
        """
        offsets = set()

        for instr in self.disasm.disasm(self.image.text_data, 0):
            offset = instr.address

            if self.image.arch == "arm64":
                mnem = instr.mnemonic
                # stp x29, x30, [sp, #-N]!
                if mnem == "stp" and "x29" in instr.op_str and "x30" in instr.op_str:
                    offsets.add(offset)
                # sub sp, sp, #N
                elif mnem == "sub" and "sp" in instr.op_str:
                    offsets.add(offset)

            elif self.image.arch == "x86_64":
                mnem = instr.mnemonic
                # push rbp (common frame setup)
                if mnem == "push" and "rbp" in instr.op_str:
                    offsets.add(offset)
                # endbr64 (CET marker, function entry)
                elif mnem == "endbr64":
                    offsets.add(offset)

        return sorted(offsets)

    def extract_function(
        self, offset: int, context_bytes: int = 512
    ) -> bytes:
        """
        Extract raw bytes of the function containing the given offset.

        Searches for the function boundary containing the offset and returns
        its raw bytes, optionally padded with context.

        Args:
            offset: Byte offset within .text section
            context_bytes: Additional bytes to include after function end (unused)

        Returns:
            Raw bytes of the function

        Raises:
            ValueError: If no function contains the given offset
        """
        boundaries = self.detect()
        for boundary in boundaries:
            if boundary.start_offset <= offset < boundary.end_offset:
                end = min(boundary.end_offset + context_bytes, len(self.image.text_data))
                return self.image.text_data[boundary.start_offset : end]

        raise ValueError(
            f"No function found at offset {offset:x} in .text"
        )
