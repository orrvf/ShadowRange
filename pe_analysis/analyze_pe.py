"""Static PE metadata extraction for ShadowRange. Never executes the inspected file."""

import argparse
import hashlib
import json
from pathlib import Path

try:
    import pefile
except ImportError:
    raise SystemExit("Missing dependency: install with 'py -3 -m pip install pefile'")

MAX_FILE_BYTES = 100 * 1024 * 1024


def analyze(path):
    if not path.is_file():
        raise ValueError(f"File not found: {path}")
    size = path.stat().st_size
    if not 0 < size <= MAX_FILE_BYTES:
        raise ValueError("File must be between 1 byte and 100 MiB")

    sha256 = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            sha256.update(chunk)

    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ])
        machine = pe.FILE_HEADER.Machine
        architecture = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}.get(machine, f"unknown (0x{machine:04x})")
        sections = []
        for section in pe.sections:
            flags = section.Characteristics
            sections.append({
                "name": section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                "virtual_address": f"0x{section.VirtualAddress:x}",
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "permissions": {
                    "read": bool(flags & 0x40000000),
                    "write": bool(flags & 0x80000000),
                    "execute": bool(flags & 0x20000000),
                },
            })

        imports = []
        for library in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            imports.append({
                "dll": library.dll.decode("ascii", errors="replace"),
                "functions": [
                    entry.name.decode("ascii", errors="replace") if entry.name else f"ordinal:{entry.ordinal}"
                    for entry in library.imports
                ],
            })

        return {
            "tool": "ShadowRange PE Analyzer",
            "analysis_type": "static_pe",
            "file": str(path.resolve()),
            "size_bytes": size,
            "sha256": sha256.hexdigest(),
            "machine": architecture,
            "pe_type": "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32" if pe.OPTIONAL_HEADER.Magic == 0x10B else "unknown",
            "entry_point_rva": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}",
            "sections": sections,
            "imports": imports,
            "note": "Static metadata only; no execution, signature verification, or malware verdict.",
        }
    finally:
        pe.close()


def main():
    parser = argparse.ArgumentParser(description="Read PE headers, sections and imports without execution")
    parser.add_argument("file", type=Path, help="Local EXE or DLL path")
    parser.add_argument("--output", type=Path, help="Optional JSON output path")
    args = parser.parse_args()

    try:
        result = analyze(args.file)
        if args.output:
            if args.output.resolve() == args.file.resolve():
                raise ValueError("Output cannot overwrite the analyzed file")
            args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("ShadowRange PE Static Analysis")
        print(f"File: {result['file']}")
        print(f"Architecture: {result['machine']} ({result['pe_type']})")
        print(f"Entry point RVA: {result['entry_point_rva']}")
        print(f"Sections: {len(result['sections'])}")
        print(f"Imported DLLs: {len(result['imports'])}")
        for section in result["sections"]:
            rights = section["permissions"]
            print(f"  {section['name']}: {'R' if rights['read'] else '-'}{'W' if rights['write'] else '-'}{'X' if rights['execute'] else '-'}")
        if args.output:
            print(f"JSON output: {args.output}")
        return 0
    except (OSError, ValueError, pefile.PEFormatError) as error:
        parser.exit(1, f"PE analysis error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
