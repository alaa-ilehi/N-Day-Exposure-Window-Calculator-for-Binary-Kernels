"""
Exception hierarchy for Patch Shadow binary analysis.

All exceptions raised by the Patch Shadow modules inherit from PatchShadowError.
This allows callers to catch any Patch Shadow-specific error with a single except clause.
"""

__all__ = [
    "PatchShadowError",
    "NotAnELFError",
    "UnsupportedArchError",
    "FunctionNotFoundError",
]


class PatchShadowError(Exception):
    """Base exception for all Patch Shadow errors."""

    pass


class NotAnELFError(PatchShadowError):
    """Raised when a file is not a valid ELF binary (bad magic bytes)."""

    pass


class UnsupportedArchError(PatchShadowError):
    """Raised when the ELF file has an unsupported CPU architecture."""

    pass


class FunctionNotFoundError(PatchShadowError):
    """Raised when a function cannot be located at the given offset."""

    pass
