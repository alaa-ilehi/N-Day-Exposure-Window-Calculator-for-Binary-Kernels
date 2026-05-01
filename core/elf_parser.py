from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ELFInfo:
    path: str
    arch: str
    bits: int
    endian: str
    entry_point: int
    sections: dict = field(default_factory=dict)
    symbols: dict = field(default_factory=dict)
    text_data: bytes = b""
    text_offset: int = 0


def parse(binary_path: str) -> ELFInfo:
    path = Path(binary_path)
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    with open(binary_path, "rb") as f:
        raw = f.read(4)
        if raw[:4] != b"\x7fELF":
            raise ValueError(f"Not a valid ELF file: {binary_path}")

    with open(binary_path, "rb") as f:
        elf = ELFFile(f)

        arch = _detect_arch(elf)
        bits = elf.elfclass
        endian = "little" if elf.little_endian else "big"
        entry = elf.header.e_entry

        sections = {}
        for section in elf.iter_sections():
            sections[section.name] = {
                "offset": section["sh_offset"],
                "size": section["sh_size"],
                "addr": section["sh_addr"],
                "type": section["sh_type"],
            }

        symbols = {}
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if sym.name and sym["st_value"] != 0:
                        symbols[sym.name] = {
                            "addr": sym["st_value"],
                            "size": sym["st_size"],
                            "type": sym["st_info"]["type"],
                        }

        text_data = b""
        text_offset = 0
        if ".text" in sections:
            text_sec = elf.get_section_by_name(".text")
            text_data = text_sec.data()
            text_offset = sections[".text"]["addr"]

    return ELFInfo(
        path=binary_path,
        arch=arch,
        bits=bits,
        endian=endian,
        entry_point=entry,
        sections=sections,
        symbols=symbols,
        text_data=text_data,
        text_offset=text_offset,
    )


def _detect_arch(elf) -> str:
    machine = elf.header.e_machine
    mapping = {
        "EM_AARCH64": "arm64",
        "EM_ARM": "arm32",
        "EM_X86_64": "x86_64",
        "EM_386": "x86",
    }
    return mapping.get(machine, "unknown")