"""Whole-file comparison of one recorded target cohort, without byte filtering."""
import hashlib
from pathlib import Path, PurePosixPath


IDENTITY = ("source_sha256", "source_inputs", "build_id", "toolchain", "profile",
            "cargo_lock_sha256", "loader_lock_sha256", "target", "fixture",
            "qemu_test_exit", "signed")
LEGACY_POLICY = "git-working-tree-v1"
CURRENT_POLICY = "git-working-tree-v2-no-archived-evidence"


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _relative(text):
    _require(isinstance(text, str) and text, "missing artifact path")
    path = PurePosixPath(text)
    _require(not path.is_absolute() and str(path) == text
             and all(part not in (".", "..") for part in path.parts),
             "artifact path must be canonical and relative")
    return path


def _sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _identity(manifest):
    _require(all(key in manifest for key in IDENTITY), "incomplete build identity")
    policy = manifest.get("source_input_policy", LEGACY_POLICY)
    _require(policy in (LEGACY_POLICY, CURRENT_POLICY), "unknown source-input policy")
    rows = manifest["source_inputs"]
    _require(isinstance(rows, list) and rows, "empty source input set")
    previous = None
    digest = hashlib.sha256()
    for row in rows:
        path, sha = row["path"], row["sha256"]
        _relative(path)
        _require(policy != CURRENT_POLICY or not path.startswith("docs/status/evidence/"),
                 "archived execution evidence is outside the declared source-input policy")
        _require(previous is None or previous < path, "duplicate or unsorted source input")
        _require(isinstance(sha, str) and len(sha) == 64
                 and all(char in "0123456789abcdef" for char in sha), "invalid source digest")
        encoded = path.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
        digest.update(sha.encode("ascii"))
        previous = path
    _require(digest.hexdigest() == manifest["source_sha256"], "source-set digest differs")
    if policy == CURRENT_POLICY:
        _require(manifest["qemu_test_exit"] is True, "unsupported current build recipe")
        fixture = manifest["fixture"] if manifest["fixture"] is not None else "normal"
        fields = (manifest["toolchain"], manifest["profile"], fixture)
        _require(all(isinstance(value, str) and value and "\0" not in value for value in fields),
                 "invalid current build recipe fields")
        recipe = (f"m0-v3\0{policy}\0{manifest['source_sha256']}\0{fields[0]}\0"
                  f"{fields[1]}\0qemu-test-exit\0{fields[2]}")
        _require(hashlib.sha256(recipe.encode()).hexdigest() == manifest["build_id"],
                 "scope-bound build recipe digest differs")
    identity = {key: manifest[key] for key in IDENTITY}
    identity["source_input_policy"] = policy
    return identity


def cohort(workspace, manifest):
    """Resolve and hash every declared artifact; return only target bytes as code.

    The outer unique PID/time directory is ownership context. Keys use the exact
    path within that cohort, so nested names cannot alias. JSON and tool logs
    remain verified context artifacts with separately declared hashes.
    """
    output = Path(workspace).resolve()
    for part in ("build", "m0"):
        output = output / part
        _require(not output.is_symlink(), "symlink in artifact output root")
    kernel = _relative(manifest["kernel"]["path"])
    _require(kernel.name == "kernel.elf" and len(kernel.parts) >= 3,
             "missing Kernel cohort anchor")
    prefix = kernel.parent
    targets, metadata, seen = {}, [], set()
    records = [(kind, manifest[kind]) for kind in ("kernel", "loader", "image")]
    _require(isinstance(manifest.get("supervisor"), list), "component inventory missing")
    records.extend(("component", row) for row in manifest["supervisor"])
    for kind, row in records:
        relative = _relative(row["path"])
        _require(relative.is_relative_to(prefix), "artifact is outside its Kernel cohort")
        logical = str(relative.relative_to(prefix))
        _require(logical != "." and logical not in seen, "duplicate cohort artifact key")
        seen.add(logical)
        path = output
        for part in relative.parts:
            path = path / part
            _require(not path.is_symlink(), "symlink in recorded artifact path")
        _require(path.is_file(), "recorded artifact missing")
        actual = _sha(path)
        _require(actual == row["sha256"], "recorded artifact digest differs")
        record = {"logical_path": logical, "path": str(path), "sha256": actual,
                  "bytes": path.stat().st_size}
        if kind != "component" or relative.suffix in (".elf", ".bin", ".zion"):
            key = kind if kind != "component" else "component:" + logical
            targets[key] = record
        else:
            _require(relative.suffix in (".json", ".log"), "unknown component artifact kind")
            metadata.append(record)
    return targets, metadata


def compare(a_workspace, a_manifest, b_workspace, b_manifest):
    """Verify source/recipe identities and compare actual entire artifact files."""
    identity = _identity(a_manifest)
    _require(identity == _identity(b_manifest), "source or recipe identity differs")
    a, a_metadata = cohort(a_workspace, a_manifest)
    b, b_metadata = cohort(b_workspace, b_manifest)
    _require(a.keys() == b.keys(), "target component artifact set differs")
    comparisons = {}
    for key, left in a.items():
        right = b[key]
        equal = left["bytes"] == right["bytes"]
        with Path(left["path"]).open("rb") as one, Path(right["path"]).open("rb") as two:
            while equal:
                chunk = one.read(1024 * 1024)
                if chunk != two.read(1024 * 1024):
                    equal = False
                if not chunk:
                    break
        comparisons[key] = {"identical": equal, "a_sha256": left["sha256"],
                            "b_sha256": right["sha256"], "bytes": left["bytes"],
                            "a_bytes": left["bytes"], "b_bytes": right["bytes"],
                            "a": left["path"], "b": right["path"],
                            "logical_path": left["logical_path"]}
    return {"comparisons": comparisons, "identity": identity,
            "context_metadata": {"a": a_metadata, "b": b_metadata},
            "method": "Full binary bytes and independently verified manifest digests; "
                      "Kernel, EFI loader, unsigned image and all recorded .elf/.bin/.zion "
                      "components. Verified .json/.log context artifacts are listed separately; "
                      "their host/run paths are not target code. Host image-builder executable "
                      "is a recorded tool, outside this target-artifact gate."}
