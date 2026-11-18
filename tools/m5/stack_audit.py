#!/usr/bin/env python3
"""Inspect actual linked x86-64 stack frames; this is not a formal stack bound.

Usage: python3 tools/m5/stack_audit.py [--userspace [--stack-bytes 16384|32768] [--stack-first-page 256|480]] ELF OUTPUT_JSON
The report is created exclusively and made read-only. Existing proof is never
replaced. This preflight rejects a resolved full-entry reference census at or
above the unchanged 256 KiB boot stack, including _start and the loader adapter.
Unresolved indirect calls, cycles and raw assembly remain explicit limitations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

BOOT_STACK_BYTES = 256 * 1024
USER_STACK_BYTES = 16 * 1024


def instruction(line):
    """GNU objdump instruction and comment, without conflating byte continuations."""
    fields = line.split("\t")
    if len(fields) < 3:
        return "", ""
    raw = fields[-1].strip()
    code, _, comment = raw.partition("#")
    return code.strip(), comment.strip()


def functions(path):
    text = subprocess.check_output(["objdump", "-d", "-C", "-w", str(path)], text=True)
    result = {}
    current = None
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]+) <(.+)>:", line)
        if match:
            current = match.group(2)
            if current in result:
                # Rust may link distinct local monomorphized bodies with the
                # same demangled name. Retain every address instead of silently
                # replacing one of the actual frames/reference targets.
                current += f" [0x{match.group(1)}]"
            if current in result:
                raise ValueError(f"duplicate linked symbol/address: {current}")
            result[current] = {"address": int(match.group(1), 16), "lines": []}
        elif current:
            result[current]["lines"].append(line)
    if not result:
        raise ValueError("no linked GNU disassembly symbols")
    return result


def frame_at(lines, start):
    """One fixed prologue, including LLVM's r11 probe loop exactly once."""
    saved, reserved = 0, 0
    probing = False
    prologue = []
    for line in lines[start:start + 150]:
        code, _ = instruction(line)
        if not code:
            continue
        if re.fullmatch(r"push[q]?\s+%\w+", code):
            saved += 8
        elif re.fullmatch(r"mov[q]?\s+%rsp,%(?:rbp|r11)", code):
            pass
        elif match := re.fullmatch(r"sub[q]?\s+\$0x([0-9a-f]+),%r11", code):
            if probing:
                raise ValueError("nested/unrecognized stack probe")
            reserved += int(match.group(1), 16)
            probing = True
        elif match := re.fullmatch(r"sub[q]?\s+\$0x([0-9a-f]+),%rsp", code):
            if not probing:
                reserved += int(match.group(1), 16)
        elif re.fullmatch(r"(?:mov[q]?|or[q]?)\s+\$0x0,\(%rsp\)", code):
            pass
        elif re.fullmatch(r"cmp[q]?\s+%r11,%rsp", code) and probing:
            pass
        elif re.match(r"jne\s", code) and probing:
            probing = False
        else:
            break
        prologue.append(line)
    if probing:
        raise ValueError("unterminated/unrecognized stack probe prologue")
    return {"reserved_bytes": reserved, "saved_register_and_return_bytes": saved + 8,
            "frame_bytes": reserved + saved + 8, "prologue": prologue,
            "prologue_line_offset": start}


def frame(function):
    # Release LLVM may shrink-wrap a frame AFTER cheap entry refusal branches.
    # Force-frame-pointers makes each such Rust prologue start with push %rbp.
    # Keep the maximum real linked fixed frame rather than treating that entry
    # branch as evidence that the successful body uses only its return slot.
    lines = function["lines"]
    starts = {0}
    starts.update(index for index, line in enumerate(lines)
                  if re.fullmatch(r"push[q]?\s+%rbp", instruction(line)[0]))
    return max((frame_at(lines, start) for start in starts),
               key=lambda value: value["frame_bytes"])


def load_pointer_reader(data):
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
        raise ValueError("expected little-endian ELF64")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or count > 256 or offset + count * size > len(data):
        raise ValueError("invalid ELF program headers")
    loads = []
    for index in range(count):
        kind, _, body, address, _, length, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + index * size)
        if kind == 1:
            if body + length > len(data):
                raise ValueError("ELF LOAD bytes outside file")
            loads.append((address, body, length))

    def pointer(address):
        for start, body, length in loads:
            if start <= address and address + 8 <= start + length:
                return struct.unpack_from("<Q", data, body + address - start)[0]
        return None
    return pointer


def verify_user_stack(data, stack_bytes, stack_first_page=256):
    """Check the exact named private RW/NX zero stack LOAD and both guards."""
    if stack_bytes not in (16384, 32768):
        raise ValueError("userspace stack must select16KiB or32KiB")
    if stack_first_page not in (256, 480):
        raise ValueError("userspace stack must select legacy page256 or M8 page480")
    load_pointer_reader(data)  # shared strict bounded ELF64 header preflight
    if struct.unpack_from("<H",data,18)[0] != 62:
        raise ValueError("userspace stack check requires x86-64 ELF")
    phoff = struct.unpack_from("<Q",data,32)[0]
    phsize, phnum = struct.unpack_from("<HH",data,54)
    start = (1 << 39) + stack_first_page * 4096
    end = start + stack_bytes
    stack = None
    for index in range(phnum):
        kind, flags, body, address, _, filesz, memsz, alignment = struct.unpack_from(
            "<IIQQQQQQ",data,phoff + index * phsize)
        if kind != 1:
            continue
        if address == start:
            if stack is not None or flags != 6 or filesz != 0 or memsz != stack_bytes or alignment != 4096:
                raise ValueError("private stack LOAD must be exact zero-initializedRW/NX extent")
            stack = index
        elif address < end + 4096 and address + memsz > start - 4096:
            raise ValueError("other LOAD overlaps private stack or guards")
    if stack is None:
        raise ValueError("declared private stack LOAD missing")
    return {"start":start,"first_page":stack_first_page,"bytes":stack_bytes,"pages":stack_bytes//4096,
            "lower_guard":start-4096,"upper_guard":end,
            "zero_initialized_rw_nx":True,"other_loads_excluded_from_stack_and_guards":True}


def references(found, pointer):
    by_address = {}
    for name, function in found.items():
        by_address.setdefault(function["address"], name)
    graph = {name: set() for name in found}
    unresolved, resolved = {}, []
    for name, function in found.items():
        regs = {}
        calls = []
        moves = []
        for line in function["lines"]:
            code, comment = instruction(line)
            if not code:
                continue
            match = re.match(r"(?:call[q]?|jmp[q]?)\s+([a-f0-9]+)\s", code)
            if match and int(match.group(1), 16) in by_address:
                graph[name].add(by_address[int(match.group(1), 16)])
            for raw in re.findall(r"\$0x([a-f0-9]{1,16})\b", code):
                if int(raw, 16) in by_address:
                    graph[name].add(by_address[int(raw, 16)])
            if re.match(r"call[q]?\s+\*", code):
                calls.append((line, code, comment))
            target = None
            match = re.fullmatch(r"(mov|movabs|lea)[q]?\s+.+,%(r[a-z0-9]+)", code)
            if match:
                addressed = re.match(r"([a-f0-9]+)\b", comment)
                if addressed:
                    address = int(addressed.group(1), 16)
                    target = address if match.group(1).startswith("lea") else pointer(address)
                immediate = re.search(r"\$0x([a-f0-9]{1,16}),", code)
                if immediate:
                    target = int(immediate.group(1), 16)
                if target in by_address:
                    regs.setdefault(match.group(2), set()).add(by_address[target])
            match = re.fullmatch(r"mov[q]?\s+%(r[a-z0-9]+),%(r[a-z0-9]+)", code)
            if match:
                moves.append(match.groups())
        for _ in range(32):
            changed = False
            for source, destination in moves:
                previous = len(regs.get(destination, set()))
                regs.setdefault(destination, set()).update(regs.get(source, set()))
                changed |= len(regs[destination]) != previous
            if not changed:
                break
        for line, code, comment in calls:
            targets = set()
            match = re.search(r"\(%rip\)", code)
            addressed = re.match(r"([a-f0-9]+)\b", comment)
            if match and addressed:
                address = pointer(int(addressed.group(1), 16))
                if address in by_address:
                    targets.add(by_address[address])
            match = re.fullmatch(r"call[q]?\s+\*%(r[a-z0-9]+)", code)
            if match:
                targets.update(regs.get(match.group(1), set()))
            if targets:
                graph[name].update(targets)
                resolved.append({"caller": name, "instruction": line,
                                 "callees": sorted(targets)})
            else:
                unresolved.setdefault(name, []).append(line)
    return graph, unresolved, resolved


def census(graph, frames, root):
    """Collapse cycles to a conservative one-visit sum, then find the DAG path.

    Cycle sums do NOT bound recursion counts. They merely prevent a cycle cut
    from silently omitting a large frame; all cycles remain in the report.
    """
    index = 0
    indices, low = {}, {}
    stack, on_stack, components = [], set(), []

    def visit(node):
        nonlocal index
        indices[node] = low[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for child in sorted(graph[node]):
            if child not in indices:
                visit(child)
                low[node] = min(low[node], low[child])
            elif child in on_stack:
                low[node] = min(low[node], indices[child])
        if low[node] == indices[node]:
            group = []
            while True:
                child = stack.pop()
                on_stack.remove(child)
                group.append(child)
                if child == node:
                    break
            components.append(sorted(group))
    visit(root)
    membership = {node: number for number, group in enumerate(components) for node in group}
    cache = {}

    def deepest(number):
        if number in cache:
            return cache[number]
        group = components[number]
        next_components = {membership[child] for node in group for child in graph[node]
                           if membership[child] != number}
        child_size, child_chain = max((deepest(child) for child in next_components),
                                     key=lambda item: item[0], default=(0, []))
        size = sum(frames[node]["frame_bytes"] for node in group)
        chain = [{"symbols": group, "frame_bytes": size,
                  "cycle": len(group) > 1 or any(node in graph[node] for node in group)}, *child_chain]
        cache[number] = size + child_size, chain
        return cache[number]
    total, chain = deepest(membership[root])
    return total, chain, [group for group in components if len(group) > 1 or any(node in graph[node] for node in group)], sorted(membership)


def exclusive_report(path, report):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    path.chmod(0o444)


def main_observer_edges(found, graph, unresolved):
    edges = []
    profiles = [
        (("desktop_runtime::Runtime", "native_runtime::"),
         ("evrosion_kernel::desktop_observation",
          "evrosion_kernel::session_observation",)),
        (("provider_runtime::Runtime", "provider_runtime::world"),
         ("evrosion_kernel::provider_observation::observation",
          "evrosion_kernel::ipc_bench_observation::observation",)),
    ]
    for caller in unresolved:
        for runtime_markers, observer_markers in profiles:
            if any(marker in caller for marker in runtime_markers):
                for callback in found:
                    if any(marker in callback for marker in observer_markers):
                        graph[caller].add(callback)
                        edges.append({"caller": caller, "callee": callback,
                                      "reason": "source-defined concrete main serial observer may be reached by this runtime's unresolved dispatch"})
    return edges


def audit(path, userspace=False, user_stack_bytes=USER_STACK_BYTES, user_stack_first_page=256):
    found = functions(path)
    required_symbols = ["_start"] if userspace else ["_start", "evrosion_kernel_entry"]
    for required in required_symbols:
        if required not in found:
            raise ValueError(f"missing actual linked entry: {required}")
    adapters = [] if userspace else [name for name in found if "__evrosion_loader_adapter::enter" in name]
    if not userspace and len(adapters) != 1:
        raise ValueError("expected exactly one actual linked loader adapter")
    data = path.read_bytes()
    if not userspace and user_stack_first_page != 256:
        raise ValueError("declared private stack page requires userspace mode")
    if userspace:
        if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
            raise ValueError("expected little-endian ELF64")
        if found["_start"]["address"] != struct.unpack_from("<Q", data, 24)[0]:
            raise ValueError("userspace _start symbol does not match ELF entry e_entry")
    user_stack = verify_user_stack(data,user_stack_bytes,user_stack_first_page) if userspace else None
    frames = {name: {"address": f"0x{function['address']:x}", **frame(function)}
              for name, function in found.items()}
    graph, unresolved, resolved = references(found, load_pointer_reader(data))
    # Main passes concrete serial observers to these bounded fixtures. Trait
    # dispatch remains listed unresolved: source-defined edges supplement that
    # list without claiming arbitrary callbacks or their nesting are proved.
    callback_edges = main_observer_edges(found, graph, unresolved)
    total, chain, cycles, reachable = census(graph, frames, "_start")
    if not all(required in reachable for required in [*adapters,*required_symbols]):
        raise ValueError("resolved full-entry graph does not include required actual entries")
    selected = [name for name in reachable if any(marker in name for marker in
                ["desktop_runtime::world", "native_runtime::", "desktop_observation", "session_observation",
                 "provider_runtime::", "provider_observation::", "ipc_bench_observation::",
                 "user_runtime::resume_context", "ev_exception_dispatch"])]
    if userspace:
        selected = [node for row in chain for node in row["symbols"]]
        selected += sorted(reachable,key=lambda name:frames[name]["frame_bytes"],reverse=True)[:12]
    selected = sorted(set([*required_symbols,*adapters,*selected]))
    stack_bytes = user_stack_bytes if userspace else BOOT_STACK_BYTES
    scope = (f"Actual linked userspace fixed-prologue and resolved code-reference census from _start, against the declared guarded{user_stack_bytes//1024}KiB stack. "
        if userspace else "Actual linked kernel fixed-prologue and resolved code-reference census from _start through loader and kernel entry. ")
    report = {
        "schema": 1,
        "scope": scope + "Not a formal whole-program, recursion, interrupt or runtime high-water bound.",
        "mode": "userspace" if userspace else "kernel",
        "elf": str(path), "elf_sha256": hashlib.sha256(data).hexdigest(),
        "analyzer": {"path": str(Path(__file__)),
                     "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "stack_bytes": stack_bytes,
        "resolved_full_entry_bytes": total,
        "margin_bytes": stack_bytes - total,
        "passed": total < stack_bytes,
        "resolved_full_entry_chain": chain,
        "selected_frames": [{"symbol": name, **frames[name]} for name in selected],
        "reachable_functions": len(reachable),
        "resolved_indirect_calls": resolved,
        "unresolved_indirect_calls": {name: unresolved[name] for name in reachable if name in unresolved},
        "cycles": cycles,
        "manual_main_observer_edges": callback_edges,
        "limitations": [
            "Every fixed prologue includes its return address; inline storage belongs to its retained parent frame. Code-address references and tail jumps are conservatively treated as nested.",
            "Cycles are collapsed with one sum of their frames, which does not bound recursive repetition. Unresolved trait/indirect targets remain unproved.",
            "CPL3 traps switch to a separate actual16KiB ENTRY_STACK; the controller resume path restores its saved RSP on capture. Raw assembly and panic/format paths need separate review.",
            "Only recognized fixed prologues, including late shrink-wrapped prologues, are counted; dynamic/body stack adjustments and asynchronous nesting are not a whole-program bound. No measured high-water mark is claimed.",
        ],
    }
    report["user_stack_bytes" if userspace else "boot_stack_bytes"] = stack_bytes
    if userspace:
        report["user_stack_layout"] = user_stack
        report["limitations"].append("Userspace entry/trampoline assembly may reset RSP; conservatively adding its linked frames is not an assertion of a physically nested initial chain. No kernel/TSS frame is charged to this private user stack.")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--userspace", action="store_true")
    parser.add_argument("--stack-bytes", type=int, choices=(16384,32768))
    parser.add_argument("--stack-first-page", type=int, choices=(256,480))
    parser.add_argument("elf", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    if (arguments.stack_bytes is not None or arguments.stack_first_page is not None) and not arguments.userspace:
        parser.error("Kernel stack budget is fixed256KiB; stack declarations require --userspace")
    userspace = arguments.userspace
    source,target = arguments.elf,arguments.output
    if target.exists():
        raise SystemExit(f"refusing to replace existing stack evidence: {target}")
    report = audit(source,userspace,arguments.stack_bytes or USER_STACK_BYTES,arguments.stack_first_page or 256)
    exclusive_report(target, report)
    print(json.dumps({key: report[key] for key in
                      ["scope", "mode", "elf_sha256", "resolved_full_entry_bytes", "stack_bytes", "margin_bytes", "passed"]}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
