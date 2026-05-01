# Patch Shadow

Version-based vulnerability scanners fail on OEM Android kernels because vendors diverge
from mainline and version numbers become meaningless. A device can run kernel 5.10 and still
carry an unpatched UAF from 2021 because the fix never made it into the shipped binary.

Patch Shadow answers a different question: does this specific binary blob contain the actual
patch commit or not. It extracts functions from a stripped kernel image, normalizes the
disassembly into an architecture-agnostic IR, and compares against known pre/post patch
signatures at the instruction level.

## What it checks

- CVE-2022-20421 — Binder UAF, Android kernel, CVSS 7.8
- CVE-2023-0266 — ALSA UAF, Linux kernel, CVSS 7.8  
- CVE-2022-2588 — cls_route UAF, net subsystem, CVSS 7.8

## Install

```bash
poetry install
```

## Usage

```bash
poetry run patch-shadow scan path/to/kernel.bin
poetry run patch-shadow scan path/to/kernel.bin --output json
```

## Limitations

- ARM64 and x86_64 only
- Function detection in stripped binaries is heuristic and will miss some boundaries
- Confidence scores below 0.75 should be verified manually
- Fingerprints cover upstream patches only, not vendor backports