#!/usr/bin/env python3
"""Inventory both locked Cargo graphs and preserve upstream license/notice files.

Run after cargo fetch --locked and the first image-builder build. --check is
read-only and verifies the committed inventory without requiring Cargo's cache.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tomllib

ROOT = Path(__file__).resolve().parents[1]
LOCKS = ("Cargo.lock", "third_party/bootloader-uefi.Cargo.lock")
INVENTORY = ROOT / "third_party/cargo-dependencies.json"


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def locked_packages():
    packages = {}
    for lock in LOCKS:
        for package in tomllib.loads((ROOT / lock).read_text())["package"]:
            if "source" not in package and package["name"] != "bootloader-x86_64-uefi":
                continue
            key = (package["name"], package["version"])
            if key not in packages:
                packages[key] = {**package, "lockfiles": []}
            packages[key]["lockfiles"].append(lock)
    return packages


def check():
    inventory = json.loads(INVENTORY.read_text())
    packages = locked_packages()
    actual = {(p["name"], p["version"]): p for p in inventory["packages"]}
    assert len(actual) == len(inventory["packages"]), "duplicate inventory record"
    assert actual.keys() == packages.keys(), "inventory does not cover both lockfiles"
    for key, package in packages.items():
        record = actual[key]
        assert record["lockfiles"] == package["lockfiles"], key
        if "checksum" in package:
            assert record["checksum"] == package["checksum"], key
        assert record["license"] and record["license_files"], f"missing license: {key}"
        for file in record["license_files"]:
            path = (ROOT / file["path"]).resolve()
            assert path.is_relative_to(ROOT / "LICENSES/third-party"), path
            assert digest(path) == file["sha256"], path
    assert digest(ROOT / LOCKS[1]) == inventory["loader_lock_sha256"]
    print(f"PASS dependency inventory: {len(actual)} packages; both lockfiles and license hashes checked")


def refresh():
    cache = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "registry/src"
    records = []
    for (name, version), package in sorted(locked_packages().items()):
        directories = list(cache.glob(f"*/{name}-{version}"))
        if len(directories) != 1:
            raise RuntimeError(f"fetch {name} {version} first (expected one cached source, found {len(directories)})")
        source = directories[0]
        metadata = tomllib.loads((source / "Cargo.toml").read_text())["package"]
        if name == "bootloader-x86_64-uefi":
            assert (source / "Cargo.lock").read_bytes() == (ROOT / LOCKS[1]).read_bytes(), "loader lock differs from published crate"
        pattern = re.compile(r"^(license|licence|copying|notice|copyright|ofl|unlicense|patents|authors)([._-].*|$)", re.I)
        files = {p for p in source.rglob("*") if p.is_file() and
                 (pattern.match(p.name) or any(part.lower() == "licenses" for part in p.relative_to(source).parts[:-1]))}
        license_source = source
        note = "License/notice files copied unchanged from this published crate."
        if not files and name.startswith("bootloader") and version == "0.11.17":
            license_source = source.parent / "bootloader-0.11.17"
            files = set(license_source.glob("LICENSE-*"))
            note = "Subcrate omits license texts; using the shared repository's root licenses from bootloader 0.11.17."
        if not files and name == "usize_conversions" and version == "0.2.0":
            license_source = source.parent / "bootloader-0.11.17"
            files = {license_source / "LICENSE-APACHE"}
            note = "Upstream declares MIT/Apache-2.0 but ships no license texts or copyright notice. Standard Apache-2.0 text is supplied from bootloader's LICENSE-APACHE; the original Cargo declaration is preserved separately. No upstream MIT notice has been invented."
        if metadata.get("license-file"):
            files.add(source / metadata["license-file"])
        if not files:
            raise RuntimeError(f"no upstream license text for {name} {version}")
        notices = []
        for path in sorted(files):
            destination = ROOT / "LICENSES/third-party" / f"{name}-{version}" / path.relative_to(license_source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            notices.append({"path": destination.relative_to(ROOT).as_posix(), "sha256": digest(destination)})
        if name == "usize_conversions":
            destination = ROOT / "LICENSES/third-party" / f"{name}-{version}" / "NOTICE-Cargo.toml"
            shutil.copyfile(source / "Cargo.toml.orig", destination)
            notices.append({"path": destination.relative_to(ROOT).as_posix(), "sha256": digest(destination)})
        if name == "noto-sans-mono-bitmap":
            destination = ROOT / "LICENSES/third-party" / f"{name}-{version}" / "OFL-Noto.txt"
            notices.append({"path": destination.relative_to(ROOT).as_posix(), "sha256": digest(destination),
                "source": "https://raw.githubusercontent.com/notofonts/noto-fonts/main/LICENSE"})
            note += " Rasterized Noto glyphs also use OFL-1.1, as described by the crate README; the Noto project notice is retained separately."
        checksum = package.get("checksum") or digest(cache.parent / "cache" / source.parent.name / f"{name}-{version}.crate")
        records.append({"name": name, "version": version, "license": metadata.get("license") or "SEE LICENSE FILE",
            "registry": package.get("source", "registry+https://github.com/rust-lang/crates.io-index"),
            "checksum": checksum, "repository": metadata.get("repository"), "lockfiles": package["lockfiles"],
            "license_files": notices, "license_source_note": note,
            "scope": "Locked host/adapter graph and/or separately locked temporary UEFI loader graph, including optional packages; lockfiles identify membership.",
            "replacement": "Host dependencies stay behind ev/image-builder; loader and handoff dependencies are replaced together under EXC-0001 before boot-contract Preview."})
    inventory = {"recorded": "2026-09-21", "loader_lock_sha256": digest(ROOT / LOCKS[1]), "packages": records}
    INVENTORY.write_text(json.dumps(inventory, indent=2) + "\n")
    check()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check()
    else:
        refresh()
