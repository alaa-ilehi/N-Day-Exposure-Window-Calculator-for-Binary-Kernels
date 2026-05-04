"""
Binary loader for kernel images.

Parses ELF headers and extracts architecture-specific sections from stripped kernel binaries.
"""

from pathlib import Path
from typing import ClassVar
from elftools.elf.elffile import ELFFile

from .exceptions import NotAnELFError, UnsupportedArchError

__all__ = ["KernelImage"]


class KernelImage:
    """
    Represents a loaded kernel binary image with architecture and text section info.

    Attributes:
        arch: CPU architecture string ("arm64" or "x86_64")
        text_data: Raw bytes of the .text section
        text_offset: File offset of the .text section start
    """

    ELF_MAGIC: ClassVar[bytes] = b"\x7fELF"

    def __init__(
        self, arch: str, text_data: bytes, text_offset: int
    ) -> None:
        """
        Initialize a KernelImage.

        Args:
            arch: CPU architecture ("arm64" or "x86_64")
            text_data: Raw bytes from the .text section
            text_offset: File offset where .text section begins
        """
        self.arch = arch
        self.text_data = text_data
        self.text_offset = text_offset

    @classmethod
    def from_file(cls, path: Path) -> "KernelImage":
        """
        Load and parse a kernel image from an ELF binary file.

        Args:
            path: Path to the ELF binary file

        Returns:
            KernelImage instance

        Raises:
            NotAnELFError: If the file is not a valid ELF binary
            UnsupportedArchError: If the CPU architecture is not supported
        """
        path = Path(path)

        # Check ELF magic bytes
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != cls.ELF_MAGIC:
                raise NotAnELFError(
                    f"Not an ELF file: {path} (bad magic bytes)"
                )

        # Parse ELF
        with open(path, "rb") as f:
            try:
                elf = ELFFile(f)
            except Exception as e:
                raise NotAnELFError(f"Failed to parse ELF: {path}") from e

            # Detect architecture
            machine = elf.header["e_machine"]
            if machine == "ARM64":
                arch = "arm64"
            elif machine == "x64":
                arch = "x86_64"
            else:
                raise UnsupportedArchError(
                    f"Unsupported architecture: {machine}"
                )

            # Extract .text section
            text_section = elf.get_section_by_name(".text")
            if not text_section:
                raise NotAnELFError(
                    f"No .text section found in {path}"
                )

            text_data = text_section.data()
            text_offset = text_section["sh_offset"]

        return cls(arch=arch, text_data=text_data, text_offset=text_offset)
