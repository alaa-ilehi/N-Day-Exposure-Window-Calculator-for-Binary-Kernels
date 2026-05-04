"""
Patch Shadow core binary analysis module.

Provides utilities for parsing, disassembling, and analyzing kernel binaries.
"""

from .exceptions import (
    FunctionNotFoundError,
    NotAnELFError,
    PatchShadowError,
    UnsupportedArchError,
)
from .loader import KernelImage
from .function_detector import FunctionDetector
from .disassembler import Disassembler
from .ir import IRFunction, IRInstruction

__all__ = [
    "KernelImage",
    "FunctionDetector",
    "Disassembler",
    "IRFunction",
    "IRInstruction",
    "PatchShadowError",
    "NotAnELFError",
    "UnsupportedArchError",
    "FunctionNotFoundError",
]
