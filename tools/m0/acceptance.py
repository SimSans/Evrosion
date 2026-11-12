#!/usr/bin/env python3
"""M0 workflows invoked by ev. No acceptance result is inferred from source presence."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
EV = [os.environ["EV_FRONTEND"]] if os.environ.get("EV_FRONTEND") else ["cargo", "ev"]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def directory(kind):
    path = ROOT / "build/m0/evidence" / f"{kind}-{os.getpid()}-{time.time_ns()}"
    path.mkdir(parents=True)
    print(f"Evidence: {path}", flush=True)
    return path


def command(args, log, cwd=ROOT, timeout=1800):
    started = time.monotonic()
    env = dict(os.environ, LC_ALL="C", TZ="UTC", CARGO_TERM_COLOR="never", PYTHONDONTWRITEBYTECODE="1")
    env.pop("CARGO_TARGET_DIR", None)
    env.pop("CARGO_BUILD_TARGET_DIR", None)
    with log.open("wb") as output:
        process = subprocess.Popen([str(x) for x in args], cwd=cwd, env=env,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    result = {"command": [str(x) for x in args], "cwd": str(cwd), "exit_status": status,
              "passed": status == 0, "duration_seconds": round(time.monotonic() - started, 3),
              "log": str(log.relative_to(ROOT)), "sha256": digest(log)}
    print(f"{'PASS' if status == 0 else 'FAIL'} {' '.join(str(x) for x in args)} ({result['duration_seconds']}s); {log}", flush=True)
    return result


def bootstrap():
    path = directory("bootstrap")
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]
    results = [command(["rustup", "toolchain", "install", pin["channel"], "--profile", pin["profile"],
                        "--component", ",".join(pin["components"]), "--target", ",".join(pin["targets"])], path / "rustup.log")]
    results.append(command(EV + ["doctor"], path / "doctor.txt"))
    write(path / "results.json", {"schema": 1, "passed": all(x["passed"] for x in results), "checks": results})
    return all(x["passed"] for x in results)


def repro():
    path = directory("repro")
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT)
    if dirty:
        write(path / "results.json", {"schema": 1, "passed": False, "error": "reproducibility requires a committed, clean source tree"})
        print("FAIL: commit/review the candidate revision before comparing clean builds", flush=True)
        return False
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    builds = []
    checks = []
    for label in ["a", "b"]:
        clone = path / f"source-{label}"
        check = command(["git", "clone", "--no-hardlinks", "--local", ROOT, clone], path / f"clone-{label}.log")
        checks.append(check)
        if not check["passed"]:
            break
        # Each clone starts with no target/build directories and compiles the loader again.
        if (clone / "target").exists() or (clone / "build").exists():
            raise RuntimeError("independent clone unexpectedly contains build products")
        check = command(["cargo", "ev", "build"], path / f"build-{label}.log", cwd=clone)
        checks.append(check)
        if not check["passed"]:
            break
        manifest = json.loads((clone / "build/m0/manifest.json").read_text())
        write(path / f"manifest-{label}.json", manifest)
        if manifest["source_dirty"] or manifest["source_revision"] != head:
            raise RuntimeError("clean build source identity mismatch")
        checks.append(command(["cargo", "ev", "doctor"], path / f"doctor-{label}.txt", cwd=clone))
        builds.append((clone, manifest))
    comparisons = {}
    if len(builds) == 2:
        for artifact in ["kernel", "loader", "image"]:
            a, b = [clone / "build/m0" / manifest[artifact]["path"] for clone, manifest in builds]
            # Actual byte comparison, as well as independent digests; no masked regions.
            equal = a.stat().st_size == b.stat().st_size
            with a.open("rb") as left, b.open("rb") as right:
                while equal:
                    chunk = left.read(1024 * 1024)
                    if chunk != right.read(1024 * 1024):
                        equal = False
                    if not chunk:
                        break
            comparisons[artifact] = {"identical": equal, "a_sha256": digest(a), "b_sha256": digest(b),
                                     "bytes": a.stat().st_size, "a": str(a.relative_to(ROOT)), "b": str(b.relative_to(ROOT))}
    if len(builds) == 2:
        clone = builds[0][0]
        (clone / "acceptance-dirty-marker.txt").write_text("Deliberate M0 dirty-source acceptance fixture.\n")
        row = command(["cargo", "ev", "build"], path / "dirty-build.log", cwd=clone)
        dirty_manifest = json.loads((clone / "build/m0/manifest.json").read_text())
        row["passed"] = row["passed"] and dirty_manifest["source_dirty"] and "WARNING: source tree is dirty" in (path / "dirty-build.log").read_text()
        checks.append(row)
        write(path / "manifest-dirty.json", dirty_manifest)
        # Reject injected build flags with a concrete, actionable diagnostic before compilation.
        row = command(["env", "RUSTFLAGS=deliberately-rejected", clone / "target/host-tools/ev", "build"], path / "invalid-build-flags.log", cwd=clone)
        row["expected_exit_status"] = 1
        row["passed"] = row["exit_status"] == 1 and "unset RUSTFLAGS" in (path / "invalid-build-flags.log").read_text()
        checks.append(row)
    passed = len(builds) == 2 and all(x["passed"] for x in checks) and all(x["identical"] for x in comparisons.values())
    write(path / "results.json", {"schema": 1, "kind": "reproducibility", "passed": passed,
          "source_revision": head, "checks": checks, "comparisons": comparisons,
          "method": "Two Git clones, separate empty target directories, full kernel and EFI compilations; shared pinned toolchain/registry sources on one prepared host. Not a hermetic cross-host claim."})
    print(f"{'PASS' if passed else 'FAIL'} independent unsigned image comparison", flush=True)
    return passed


def architecture():
    path = directory("architecture")
    rows = [command(["python3", "tools/check_architecture.py"], path / "fitness.log"),
            command(["python3", "-m", "unittest", "discover", "-s", "tests/host", "-p", "test_*.py", "-v"], path / "negative-cases.log")]
    passed = all(row["passed"] for row in rows)
    write(path / "results.json", {"schema": 1, "passed": passed, "checks": rows,
          "note": "Repository invariants and expiry checks only. Runtime AF-001/015/M0-016/M0-017 are verified by the full M0 suite. Later milestone fitness tests remain deferred."})
    return passed


def acceptance():
    path = directory("acceptance")
    rows = []
    commands = [
        ("bootstrap", EV + ["bootstrap"]),
        ("format", ["cargo", "fmt", "--all", "--", "--check"]),
        ("host-tests", ["cargo", "test", "--locked", "--offline"]),
        ("host-clippy", ["cargo", "clippy", "--all-targets", "--locked", "--offline", "--", "-D", "warnings"]),
        ("architecture", EV + ["test", "architecture", "--milestone", "M0"]),
        ("licenses", ["python3", "tools/cargo_inventory.py", "--check"]),
        ("build", EV + ["build"]),
        ("kernel-clippy", ["cargo", "clippy", "-p", "ev-kernel", "--target", "x86_64-unknown-none", "--all-features", "--locked", "--offline", "--", "-D", "warnings"]),
        ("builder-clippy", ["cargo", "clippy", "-p", "ev-image-builder", "--all-targets", "--locked", "--offline", "--", "-D", "warnings"]),
        ("AF-001-five-boots", EV + ["test", "boot", "--runs", "5"]),
        ("debug-entry", EV + ["debug", "kernel", "--batch"]),
        ("panic-build", EV + ["build", "--fixture", "panic"]),
        ("AF-M0-016-panic", EV + ["test", "panic"]),
        ("panic-symbolization", EV + ["debug", "kernel", "--batch"]),
        ("serial-fallback-build", EV + ["build", "--fixture", "no-framebuffer"]),
        ("AF-M0-017-serial-fallback", EV + ["test", "boot", "--runs", "1"]),
        ("restore-normal-image", EV + ["build"]),
        ("AF-015-clean-independent-builds", EV + ["image", "--verify-reproducible"]),
    ]
    try:
        for name, args in commands:
            row = dict(command(args, path / f"{name}.log", timeout=3600), id=name)
            rows.append(row)
            write(path / "results.json", {"schema": 1, "kind": "acceptance", "passed": False, "running": True, "checks": rows})
            if not row["passed"]:
                break
    except Exception as error:
        rows.append({"id": "runner", "passed": False, "error": str(error)})
    passed = len(rows) == len(commands) and all(row["passed"] for row in rows)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    write(path / "results.json", {"schema": 1, "kind": "acceptance", "passed": passed, "running": False,
          "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": head,
          "checks": rows, "expected_checks": len(commands)})
    suite = ET.Element("testsuite", name="Evrosion M0", tests=str(len(rows)), failures=str(sum(not r["passed"] for r in rows)))
    for row in rows:
        case = ET.SubElement(suite, "testcase", name=row["id"], time=str(row.get("duration_seconds", 0)))
        if not row["passed"]:
            ET.SubElement(case, "failure").text = row.get("log", row.get("error", "failed"))
    ET.ElementTree(suite).write(path / "test-results.xml", encoding="utf-8", xml_declaration=True)
    print(f"{'PASS' if passed else 'FAIL'} M0 acceptance: {path / 'results.json'}", flush=True)
    return passed


if __name__ == "__main__":
    workflows = {"bootstrap": bootstrap, "repro": repro, "architecture": architecture, "acceptance": acceptance}
    if len(sys.argv) != 2 or sys.argv[1] not in workflows:
        sys.exit("Invoke through cargo ev; unsupported workflow")
    sys.exit(0 if workflows[sys.argv[1]]() else 1)
