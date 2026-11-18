"""Host the exact private ownership helper without weakening host-tool policy.

The frontend package forbids unsafe code, including its Cargo test targets.
This binary-only helper necessarily implements a reviewed UnsafeCell owner.
Compile its original test module independently with the pinned Rust toolchain;
the frontend retains its existing forbid lint and production dependencies.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RootResidentOwnership(unittest.TestCase):
    def test_actual_private_slot_ownership_and_alignment(self):
        parent = ROOT / "build/test-tmp"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="resident-slot-", dir=parent) as temporary:
            executable = Path(temporary) / "resident-tests"
            # cwd makes rustup select the repository's pinned toolchain.
            command = ["rustc", "--edition=2024", "--test",
                       str(ROOT / "services/root-supervisor/src/native/resident_slot.rs"),
                       "-Dwarnings", "-Dunsafe_op_in_unsafe_fn", "-Dunused_unsafe",
                       "-o", str(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertRegex(result.stdout, re.compile(r"test result: ok\. [1-9][0-9]* passed; 0 failed"))


if __name__ == "__main__":
    unittest.main()
