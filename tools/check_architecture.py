#!/usr/bin/env python3
"""Offline Slice 0 governance checks. Requires Python 3.11+, no packages."""

import argparse
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, date
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib
from urllib.parse import unquote, urlsplit


REQUIRED = (
    "README.md", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
    "LICENSES/README.md", ".github/workflows/ci.yml",
    "architecture/ARCHITECTURE_INDEX.md", "architecture/GOVERNANCE.md",
    "architecture/INVARIANTS.md", "architecture/glossary.md",
    "architecture/AUDIT_ACTIONS.md", "architecture/status.toml",
    "architecture/adr/README.md", "architecture/adr/ADR-0000-template.md",
    "architecture/exceptions/REGISTER.md",
    "architecture/exceptions/EXC-0001-temporary-bootloader.md",
    "architecture/exceptions/EXC-0002-host-qemu-ovmf.md",
    "architecture/designs/ROOT_AUTHORITY_CUSTODY.md",
    "architecture/designs/IPC_DISCIPLINE.md",
    "architecture/plans/source-map.json",
)
IGNORED = {".git", ".agents", ".codex", ".ev", "target", "build", "__pycache__"}
INVARIANT = re.compile(r"\bINV-[A-Z][A-Z0-9]*-\d{3}\b")
DEFINITION = re.compile(r"^- \*\*(INV-[A-Z][A-Z0-9]*-\d{3}) —", re.MULTILINE)
LINK = re.compile(r"\[[^\]\n]+\]\((<[^>\n]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)")
MATURITIES = ("Internal", "Preview", "Stable", "Deprecated", "Removed")


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)


def repository_files(root):
    for parent, directories, files in os.walk(root):
        relative = Path(parent).relative_to(root)
        directories[:] = sorted(
            name for name in directories
            if name not in IGNORED
            and relative / name not in (Path("architecture/plans"), Path("tests/fixtures"))
        )
        for name in sorted(files):
            yield Path(parent) / name


def prose(text):
    """Remove fenced examples, retaining newlines for diagnostics."""
    fence = None
    lines = []
    for line in text.splitlines():
        match = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence is None and match:
            fence = match[1]
            lines.append("")
        elif fence is not None:
            stripped = line.strip()
            if stripped and set(stripped) == {fence[0]} and len(stripped) >= len(fence):
                fence = None
            lines.append("")
        else:
            lines.append(line)
    return "\n".join(lines)


def anchors(text):
    result = set()
    for heading in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", prose(text), re.MULTILINE):
        heading = LINK.sub(lambda match: match[0].split("]", 1)[0][1:], heading)
        base = re.sub(r"[^\w -]", "", heading.lower()).replace(" ", "-")
        anchor, suffix = base, 0
        while anchor in result:
            suffix += 1
            anchor = f"{base}-{suffix}"
        result.add(anchor)
    return result


def inside(root, path):
    return path.resolve().is_relative_to(root.resolve())


def check_links(root, documents, report):
    for path, text in documents.items():
        # Inline code can contain illustrative Markdown and is not a link.
        text = re.sub(r"`[^`\n]*`", "", prose(text))
        for match in LINK.finditer(text):
            destination = match[1].strip("<>")
            url = urlsplit(destination)
            if url.scheme in ("http", "https", "mailto"):
                continue
            location = f"{path.relative_to(root)}:{text[:match.start()].count(chr(10)) + 1}"
            if url.scheme or url.netloc or url.query:
                report.errors.append(f"{location}: unsupported local link {destination}")
                continue
            target = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not inside(root, target) or not target.exists():
                report.errors.append(f"{location}: broken local link {destination}")
            elif url.fragment and target.suffix == ".md":
                if unquote(url.fragment) not in anchors(target.read_text(encoding="utf-8")):
                    report.errors.append(f"{location}: broken heading link {destination}")


def check_invariants(root, documents, report):
    register = root / "architecture/INVARIANTS.md"
    counts = Counter(DEFINITION.findall(prose(documents[register])))
    if not counts:
        report.errors.append("invariant register is empty or has no valid definitions")
    for identifier, count in counts.items():
        if count != 1:
            report.errors.append(f"duplicate invariant ID: {identifier}")
    for path, text in documents.items():
        text = prose(text)
        for identifier in sorted(set(INVARIANT.findall(text)) - counts.keys()):
            report.errors.append(f"{path.relative_to(root)}: unknown invariant {identifier}")
        if path != register and DEFINITION.search(text):
            report.errors.append(f"{path.relative_to(root)}: invariant definitions belong in INVARIANTS.md")
    report.notices.append(f"{len(counts)} invariant definitions checked (proof coverage is recorded separately)")


def check_record_ids(root, report):
    for folder, prefix in (("adr", "ADR"), ("exceptions", "EXC")):
        seen = set()
        for path in sorted((root / "architecture" / folder).glob(f"{prefix}-*.md")):
            match = re.fullmatch(rf"({prefix}-\d{{4}})-[a-z0-9-]+\.md", path.name)
            if not match:
                report.errors.append(f"invalid record filename: {path.name}")
                continue
            identifier = match[1]
            if identifier in seen:
                report.errors.append(f"duplicate record ID: {identifier}")
            seen.add(identifier)
            if identifier == "ADR-0000":
                continue  # The template intentionally uses ADR-NNNN in its heading.
            heading = path.read_text(encoding="utf-8").splitlines()[0]
            if not heading.startswith(f"# {identifier} — "):
                report.errors.append(f"{path.name}: heading and filename IDs differ")


def iso_date(value):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError(f"invalid ISO date: {value}")
    return date.fromisoformat(value)


def expired(trigger, state, today):
    if trigger == "boot-contract-preview":
        return state["boot_contract_maturity"] != "Internal"
    if trigger == "production-release":
        return state["release_ci_production_grade"] or state["reproducibility_production_grade"]
    if re.fullmatch(r"milestone:M\d+", trigger):
        return int(state["milestone"][1:]) >= int(trigger.split(":M")[1])
    if trigger.startswith("date:"):
        return today >= iso_date(trigger[5:])
    raise ValueError(f"unknown expiry trigger: {trigger}")


def check_exceptions(root, report, today):
    state = tomllib.loads((root / "architecture/status.toml").read_text(encoding="utf-8"))
    if not re.fullmatch(r"M\d+", state.get("milestone", "")):
        raise ValueError("status.toml: milestone must be M followed by a number")
    if state.get("boot_contract_maturity") not in MATURITIES:
        raise ValueError("status.toml: unknown boot contract maturity")
    for flag in ("release_ci_production_grade", "reproducibility_production_grade"):
        if type(state.get(flag)) is not bool:
            raise ValueError(f"status.toml: {flag} must be a boolean")

    directory = root / "architecture/exceptions"
    rows = {}
    for line in (directory / "REGISTER.md").read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells and re.fullmatch(r"EXC-\d{4}", cells[0]):
            if cells[0] in rows:
                report.errors.append(f"duplicate exception register ID: {cells[0]}")
            rows[cells[0]] = cells[-1]

    records = {}
    fields = ("Status", "Opened", "Owner", "Target removal", "Expiry trigger", "Affected invariants", "Scope")
    sections = ("Temporary deviation", "Why it is necessary now", "Risk and containment",
                "Removal plan", "Test preventing scope expansion", "Resolution evidence")
    for path in sorted(directory.glob("EXC-*.md")):
        text = prose(path.read_text(encoding="utf-8"))
        identifier = "-".join(path.stem.split("-")[:2])
        metadata = {}
        for name, value in re.findall(r"^([A-Za-z][A-Za-z ]+):\s*([^\n]+)$", text, re.MULTILINE):
            if name in metadata:
                report.errors.append(f"{identifier}: duplicate field {name}")
            metadata[name] = value.strip()
        missing = [name for name in fields if not metadata.get(name)]
        if missing:
            report.errors.append(f"{identifier}: missing fields: {', '.join(missing)}")
            continue
        for section in sections:
            body = re.search(rf"^## {re.escape(section)}\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
            if not body or not body[1].strip():
                report.errors.append(f"{identifier}: missing section content: {section}")
        if not INVARIANT.search(metadata["Affected invariants"]):
            report.errors.append(f"{identifier}: affected invariants must name registered IDs")
        for scope in metadata["Scope"].split(","):
            scope = scope.strip().strip("`")
            target = root / scope
            if not scope or Path(scope).is_absolute() or not inside(root, target) or not target.exists():
                report.errors.append(f"{identifier}: invalid scope path: {scope}")
        status = metadata["Status"]
        records[identifier] = status
        if status not in ("Active", "Resolved", "Expired"):
            report.errors.append(f"{identifier}: invalid status {status}")
        try:
            iso_date(metadata["Opened"])
            reached = expired(metadata["Expiry trigger"], state, today)
        except ValueError as error:
            report.errors.append(f"{identifier}: {error}")
            reached = False
        if status == "Expired" or (status == "Active" and reached):
            report.notices.append(f"{identifier}: Expired — {metadata['Target removal']}")
            report.errors.append(f"{identifier}: expired exception must be resolved")
        elif status == "Active":
            report.notices.append(f"{identifier}: Active — {metadata['Target removal']}")
    if records != rows:
        report.errors.append("exception register IDs/statuses do not match exception files")


def check_source_inventory(root, report):
    plans = root / "architecture/plans"
    manifest = plans / "source-map.json"
    documents = json.loads(manifest.read_text(encoding="utf-8"))["documents"]
    recorded, originals = set(), set()
    for entry in documents:
        path = (root / entry["path"]).resolve()
        if path in recorded or entry["original_path"] in originals:
            report.errors.append(f"duplicate source inventory entry: {entry['path']}")
        recorded.add(path)
        originals.add(entry["original_path"])
        if not inside(plans, path) or not path.is_file() or path == manifest:
            report.errors.append(f"invalid source inventory path: {entry['path']}")
            continue
        data = path.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            report.errors.append(f"source inventory checksum mismatch: {entry['path']}")
    actual = {path.resolve() for path in plans.rglob("*") if path.is_file() and path != manifest}
    if actual != recorded:
        report.errors.append("source inventory does not cover exactly the imported plan files")
    report.notices.append(f"{len(documents)} imported source documents checked")


def dependency_names(table):
    for key, value in table.items():
        if key in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, specification in value.items():
                yield specification.get("package", name) if isinstance(specification, dict) else name
        elif isinstance(value, dict):
            yield from dependency_names(value)


def check_bootloader_scope(root, files, report):
    allowed = {"bootloader": Path("boot/image-builder"), "bootloader_api": Path("libs/boot-contract")}
    for path in files:
        if path.name != "Cargo.toml":
            continue
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        for dependency in dependency_names(manifest):
            if dependency in allowed and path.parent.relative_to(root) != allowed[dependency]:
                report.errors.append(f"{path.relative_to(root)}: {dependency} exceeds EXC-0001 scope")


def validate(root, today=None):
    root = root.resolve()
    today = today or datetime.now(timezone.utc).date()
    report = Report()
    for relative in REQUIRED:
        if not (root / relative).is_file():
            report.errors.append(f"missing required file: {relative}")
    if report.errors:
        return report
    files = list(repository_files(root))
    documents = {path: path.read_text(encoding="utf-8") for path in files if path.suffix == ".md"}
    checks = (
        lambda: check_links(root, documents, report),
        lambda: check_invariants(root, documents, report),
        lambda: check_record_ids(root, report),
        lambda: check_exceptions(root, report, today),
        lambda: check_source_inventory(root, report),
        lambda: check_bootloader_scope(root, files, report),
    )
    for check in checks:
        try:
            check()
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            report.errors.append(f"invalid governance input: {error}")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        report = validate(arguments.root)
    except (OSError, ValueError) as error:
        print(f"FAIL: cannot read governance input: {error}")
        return 1
    for notice in report.notices:
        print(notice)
    for error in report.errors:
        print(f"FAIL: {error}")
    if report.errors:
        print(f"Architecture checks failed: {len(report.errors)} error(s)")
        return 1
    print("PASS: Slice 0 architecture checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
