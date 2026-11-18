"""Tests for linked frame parsing and honest reference-census boundaries."""
from pathlib import Path
import tempfile
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
import stack_audit as audit


def function(*instructions):
    return {"address": 1, "lines": [f"1:\t48 00\t{code}" for code in instructions]}


class StackAuditTests(unittest.TestCase):
    def test_probe_loop_and_inline_comments_count_whole_reserve_once(self):
        value = audit.frame(function(
            "push %rbp", "mov %rsp,%rbp", "push %r15",
            "mov %rsp,%r11", "sub $0xf000,%r11 # imm = 61440",
            "sub $0x1000,%rsp # imm = 4096", "movq $0x0,(%rsp)",
            "cmp %r11,%rsp", "jne abc <probe>", "sub $0x918,%rsp",
            "mov %rdi,%r12"))
        self.assertEqual(value["reserved_bytes"], 0xf918)
        self.assertEqual(value["frame_bytes"], 0xf918 + 24)
        self.assertEqual(audit.frame(function("push %rbp", "mov %rsp,%r11",
            "sub $0x5000,%r11", "sub $0x1000,%rsp", "jne 1", "ret"))["frame_bytes"], 0x5010)

    def test_unrolled_probe_reserves_each_page_and_bad_probe_refuses(self):
        value = audit.frame(function("push %rbp", "mov %rsp,%rbp",
            "sub $0x1000,%rsp", "movq $0x0,(%rsp)",
            "sub $0x1000,%rsp # stack page", "movq $0x0,(%rsp)",
            "sub $0xe8,%rsp", "ret"))
        self.assertEqual(value["frame_bytes"], 0x20f8)
        with self.assertRaisesRegex(ValueError, "unterminated"):
            audit.frame(function("mov %rsp,%r11", "sub $0x5000,%r11", "call 123"))

    def test_shrink_wrapped_frame_after_early_refusal_is_not_missed(self):
        value = audit.frame(function("mov %rdi,%rax", "cmp $0x60,%rdx",
            "jb 20 <early_refusal>", "ret", "push %rbp", "mov %rsp,%rbp",
            "push %r15", "push %r14", "push %r13", "push %r12", "push %rbx",
            "sub $0xa98,%rsp", "mov %rdx,%rbx"))
        self.assertEqual(value["frame_bytes"], 2768)
        self.assertEqual(value["prologue_line_offset"], 4)

    def test_distinct_same_demangled_symbols_are_all_retained(self):
        text = "10 <same>:\n10:\t55\tpush %rbp\n20 <same>:\n20:\t50\tpush %rax\n"
        with patch.object(audit.subprocess, "check_output", return_value=text):
            found = audit.functions(Path("unused"))
        self.assertEqual(len(found), 2)
        self.assertEqual({f["address"] for f in found.values()}, {0x10, 0x20})

    def test_got_register_and_direct_reference_targets_and_unresolved_are_retained(self):
        found = {
            "entry": function("call *0x10(%rip) # 100 <GOT>",
                "mov $0x30,%r12", "mov %r12,%rax",
                "call *%rax", "call 40 <direct>", "call *0x20(%rdi)"),
            "got": {"address": 0x20, "lines": []},
            "register": {"address": 0x30, "lines": []},
            "direct": {"address": 0x40, "lines": []},
        }
        graph, unresolved, resolved = audit.references(found,
            lambda address: 0x20 if address == 0x100 else None)
        self.assertEqual(graph["entry"], {"got", "register", "direct"})
        self.assertEqual(len(resolved), 2)
        self.assertEqual(len(unresolved["entry"]), 1)

    def test_full_entry_includes_loader_and_cycle_collapse_is_explicit(self):
        graph = {"_start": {"loader"}, "loader": {"entry"},
                 "entry": {"a"}, "a": {"b"}, "b": {"a", "leaf"},
                 "leaf": set()}
        frames = {name: {"frame_bytes": value} for name, value in
                  [("_start", 32), ("loader", 12544), ("entry", 60000),
                   ("a", 100000), ("b", 40000), ("leaf", 80)]}
        size, chain, cycles, reachable = audit.census(graph, frames, "_start")
        self.assertEqual(size, 212656)
        self.assertEqual(cycles, [["a", "b"]])
        self.assertEqual(chain[0]["symbols"], ["_start"])
        self.assertIn("loader", reachable)
        self.assertTrue(next(row for row in chain if row["symbols"] == ["a", "b"])["cycle"])
        _, _, self_cycles, _ = audit.census({"a": {"a"}}, {"a": {"frame_bytes": 8}}, "a")
        self.assertEqual(self_cycles, [["a"]])

    def test_userspace_stack_extent_flags_and_both_guards_are_measured(self):
        def elf(size, flags=6, extra_guard=False, first_page=256, upper_guard=False):
            data = bytearray(64+3*56)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H",data,18,62)
            struct.pack_into("<Q",data,32,64)
            struct.pack_into("<HH",data,54,56,3 if extra_guard else 2)
            base = 1 << 39
            struct.pack_into("<IIQQQQQQ",data,64,1,5,0,base+4096,0,0,4096,4096)
            struct.pack_into("<IIQQQQQQ",data,120,1,flags,0,base+first_page*4096,0,0,size,4096)
            if extra_guard:
                struct.pack_into("<IIQQQQQQ",data,176,1,6,0,base+(first_page+size//4096 if upper_guard else first_page-1)*4096,0,0,4096,4096)
            return data
        for size in [16384,32768]:
            self.assertEqual(audit.verify_user_stack(elf(size),size)["bytes"],size)
            for bad in [elf(size,7),elf(size,6,True),elf(32768 if size==16384 else 16384)]:
                with self.assertRaises(ValueError):
                    audit.verify_user_stack(bad,size)
        with self.assertRaises(ValueError):
            audit.verify_user_stack(elf(16384),65536)
        for size in [16384,32768]:
            image=elf(size,first_page=480)
            layout=audit.verify_user_stack(image,size,480)
            self.assertEqual(layout['first_page'],480)
            self.assertEqual(layout['lower_guard'],(1<<39)+479*4096)
            self.assertEqual(layout['upper_guard'],(1<<39)+(480+size//4096)*4096)
            with self.assertRaises(ValueError):
                audit.verify_user_stack(image,size) # no implicit relocation
            for bad in [elf(size,7,first_page=480),elf(size,extra_guard=True,first_page=480),elf(size,extra_guard=True,first_page=480,upper_guard=True)]:
                with self.assertRaises(ValueError):audit.verify_user_stack(bad,size,480)
            for page in [0,479,481,509]:
                with self.assertRaises(ValueError):audit.verify_user_stack(image,size,page)

    def test_unloaded_symbol_metadata_cannot_redirect_userspace_entry_census(self):
        # A real ELF and GNU disassembly exercise the audit boundary. Only the
        # unloaded _start symbol value changes; header, PH table and all LOAD
        # bytes remain exact, so a loaded-image equivalence check still passes.
        data = bytearray(0x2400)
        base = 1 << 39
        entry = base + 4096
        data[:9] = b"\x7fELF\x02\x01\x01\0\0"
        struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                         2, 62, 1, entry, 64, 0x2200, 0, 64, 56, 2, 64, 5, 4)
        struct.pack_into("<IIQQQQQQ", data, 64,
                         1, 5, 4096, entry, 0, 17, 4096, 4096)
        struct.pack_into("<IIQQQQQQ", data, 120,
                         1, 6, 8192, base + 480*4096, 0, 0, 32768, 4096)
        data[4096:4113] = bytes.fromhex("554889e54883ec204883c4205dc39090c3")
        strings = b"\0_start\0decoy\0"
        sections = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
        data[0x2000:0x2000+len(strings)] = strings
        data[0x2040:0x2040+len(sections)] = sections
        struct.pack_into("<IBBHQQ", data, 0x2118, 1, 0x12, 0, 1, entry, 14)
        struct.pack_into("<IBBHQQ", data, 0x2130, 8, 0x12, 0, 1, entry+16, 1)
        for index, row in enumerate([
            (1, 1, 6, entry, 4096, 17, 0, 0, 16, 0),
            (7, 2, 0, 0, 0x2100, 72, 3, 1, 8, 24),
            (15, 3, 0, 0, 0x2000, len(strings), 0, 0, 1, 0),
            (23, 3, 0, 0, 0x2040, len(sections), 0, 0, 1, 0),
        ], 1):
            struct.pack_into("<IIQQQQIIQQ", data, 0x2200+index*64, *row)
        bad = bytearray(data)
        struct.pack_into("<Q", bad, 0x2120, entry+15)
        self.assertEqual(data[:0x2100], bad[:0x2100])
        self.assertEqual(audit.load_pointer_reader(data)(entry),
                         audit.load_pointer_reader(bad)(entry))
        with tempfile.TemporaryDirectory() as directory:
            good = Path(directory) / "good.elf"
            foreign = Path(directory) / "foreign-start.elf"
            report = Path(directory) / "must-not-exist.json"
            good.write_bytes(data)
            foreign.write_bytes(bad)
            self.assertEqual(audit.functions(good)["_start"]["address"], entry)
            self.assertEqual(audit.functions(foreign)["_start"]["address"], entry+15)
            measured = audit.audit(good, userspace=True,
                                   user_stack_bytes=32768, user_stack_first_page=480)
            self.assertTrue(measured["passed"])
            self.assertEqual(measured["resolved_full_entry_bytes"], 48)
            result = subprocess.run([
                sys.executable, str(Path(audit.__file__)), "--userspace",
                "--stack-bytes", "32768", "--stack-first-page", "480",
                str(foreign), str(report),
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("_start symbol does not match ELF entry e_entry",
                          result.stdout + result.stderr)
            self.assertFalse(report.exists())


    def test_main_callbacks_are_explicit_and_bound_to_their_actual_runtime(self):
        desktop = "evrosion_kernel::desktop_observation"
        provider = "evrosion_kernel::provider_observation::observation"
        callers = ["evrosion_kernel::desktop_runtime::Runtime::run",
                   "evrosion_kernel::provider_runtime::Runtime::reply_rpc",
                   "unrelated::callback"]
        found = {name: {} for name in [desktop, provider, *callers]}
        graph = {name: set() for name in found}
        unresolved = {name: ["actual unresolved instruction"] for name in callers}
        edges = audit.main_observer_edges(found, graph, unresolved)
        self.assertEqual(graph[callers[0]], {desktop})
        self.assertEqual(graph[callers[1]], {provider})
        self.assertEqual(graph[callers[2]], set())
        self.assertEqual(len(edges), 2)
        self.assertEqual(unresolved[callers[1]], ["actual unresolved instruction"])

    def test_session_callback_wrapper_cannot_disappear_from_runtime_census(self):
        caller = "evrosion_kernel::desktop_runtime::Runtime::run"
        session = "evrosion_kernel::session_observation"
        desktop = "evrosion_kernel::desktop_observation"
        found = {name: {} for name in [caller, session, desktop]}
        # The wrapper calls the concrete formatter, while runtime dispatches its
        # observer through an unresolved trait object. A direct runtime->desktop
        # supplement alone would omit the wrapper's actual nested frame.
        graph = {caller: set(), session: {desktop}, desktop: set()}
        frames = {name: {"frame_bytes": size} for name, size in
                  [(caller, 128), (session, 64), (desktop, 192)]}
        audit.main_observer_edges(found, graph, {caller: ["call *%rax"]})
        total, _, _, reachable = audit.census(graph, frames, caller)
        self.assertEqual(total, 384)
        self.assertIn(session, reachable)
        self.assertEqual(graph[caller], {session, desktop})

    def test_report_is_exclusive_and_readonly(self):
        parent = Path(__file__).resolve().parents[2] / "build/test-tmp"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            path = Path(directory) / "report.json"
            audit.exclusive_report(path, {"passed": True})
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                audit.exclusive_report(path, {"passed": False})
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(path.stat().st_mode & 0o222, 0)


if __name__ == "__main__":
    unittest.main()
