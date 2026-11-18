#!/usr/bin/env python3
"""Canonical debug stripping with exact loaded identity and M8 page checks.

This is an ELF preflight, never actual loader admission or runtime qualification.
All outputs are exclusive; the original ELF and failed attempts stay retained.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def image(path):
    data = path.read_bytes()
    if data[:7] != b"\x7fELF\x02\x01\x01" or len(data) < 64:
        raise ValueError("expected ELF64 little endian v1")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if (kind, machine) != (2, 62):
        raise ValueError("expected x86-64 EXEC")
    entry, headers = struct.unpack_from("<QQ", data, 24)
    size, count = struct.unpack_from("<HH", data, 54)
    if size != 56 or not 1 <= count <= 16 or headers + size * count > len(data):
        raise ValueError("invalid program headers")
    loads, payloads, pages = [], [], set()
    base = 1 << 39
    for index in range(count):
        segment = struct.unpack_from("<IIQQQQQQ", data, headers + size * index)
        typ, flags, offset, address, physical, file_bytes, memory_bytes, align = segment
        if typ != 1:
            continue
        if flags not in (4, 5, 6) or file_bytes > memory_bytes or offset + file_bytes > len(data):
            raise ValueError("invalid or executable-writable load")
        if align != 4096 or address % 4096 != offset % 4096:
            raise ValueError("invalid load alignment")
        if not memory_bytes or address < base + 4096 or address + memory_bytes > base + 512 * 4096:
            raise ValueError("load outside admitted private region")
        current = set(range((address - base) // 4096, (address - base + memory_bytes + 4095) // 4096))
        if pages & current:
            raise ValueError("overlapping load pages")
        pages |= current
        loads.append({"flags": flags, "address": address, "physical": physical,
                      "file_bytes": file_bytes, "memory_bytes": memory_bytes,
                      "alignment": align, "bytes_sha256": sha(data[offset:offset + file_bytes])})
        payloads.append(data[offset:offset + file_bytes])
    if not loads or not any(row["flags"] == 5 and row["address"] <= entry < row["address"] + row["memory_bytes"] for row in loads):
        raise ValueError("entry is not executable")
    stack = [row for row in loads if row["address"] == base + 480 * 4096]
    if len(stack) != 1 or any(stack[0][key] != value for key, value in
        (("flags", 6), ("file_bytes", 0), ("memory_bytes", 32768), ("alignment", 4096))):
        raise ValueError("missing exact32KiB RW/NX zero stack480")
    if 479 in pages or 488 in pages or any(page >= 489 for page in pages):
        raise ValueError("stack guard or independent startup/window region overlap")
    if len(pages) > 96:
        raise ValueError("actual loaded image exceeds96-page Workspace profile")
    return {"entry": entry, "loads": loads}, {"path": str(path.resolve()), "file_bytes": len(data),
        "sha256": sha(data), "loaded_pages_including_stack": len(pages), "stack_pages": 8,
        "nonstack_loaded_pages": len(pages) - 8, "image_page_bound": 96,
        "page_bound_passed": True, "loaded_page_indices": sorted(pages)}, payloads


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("canonical", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    if args.canonical.exists() or args.report.exists():
        raise ValueError("refusing to overwrite qualification output")
    identity, original, original_payloads = image(args.original)
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    candidates = list(sysroot.glob("lib/rustlib/*/bin/llvm-objcopy"))
    if len(candidates) != 1:
        raise ValueError("expected one pinned toolchain llvm-objcopy")
    objcopy = candidates[0]
    subprocess.run([str(objcopy), "--strip-debug", str(args.original), str(args.canonical)], check=True)
    stripped_identity, canonical, canonical_payloads = image(args.canonical)
    if stripped_identity != identity or canonical_payloads != original_payloads:
        raise ValueError("canonical strip changed exact loaded identity/bytes")
    report = {"schema": 1, "scope": "Actual linked ELF preflight; not loader admission, RPC or VM qualification",
              "passed": True, "strip": "--strip-debug", "objcopy": str(objcopy),
              "objcopy_sha256": sha(objcopy.read_bytes()), "original": original,
              "canonical": canonical, "entry_and_load_identity_equal": True,
              "loaded_bytes_compared_bytewise": True,
              "qualifier": {"path": str(Path(__file__).resolve()), "sha256": sha(Path(__file__).read_bytes())},
              "load_identity": identity}
    with args.report.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    args.report.chmod(0o444)
    print(json.dumps({"passed": True, "loaded_pages": canonical["loaded_pages_including_stack"],
                      "canonical_bytes": canonical["file_bytes"], "report": str(args.report)}))


if __name__ == "__main__":
    main()
