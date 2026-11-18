#!/usr/bin/env python3
"""Complete bounded M1 kernel-spine mechanism gate; no release/publish action."""
import os
import sys
import argparse
import bootstrap
import allocation


def extra_checks(run, checks):
    allocation.extra_checks(run, checks)
    for name, command in [
        ('format', ['cargo', 'fmt', '--all', '--', '--check']),
        ('workspace-lint', ['cargo', 'clippy', '--all-targets', '--locked', '--offline', '--', '-D', 'warnings']),
        ('architecture', ['python3', 'tools/check_architecture.py']),
        ('governance-negative-cases', ['python3', '-m', 'unittest', 'discover', '-s', 'tests/host', '-p', 'test_*.py', '-v']),
        ('dependency-inventory', ['python3', 'tools/cargo_inventory.py', '--check']),
        ('status', ['python3', 'tools/status.py', '--check']),
    ]:
        run(name, command)


if __name__ == '__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    temporary = bootstrap.ROOT / 'build/test-tmp'
    temporary.mkdir(parents=True, exist_ok=True)
    os.environ['TMPDIR'] = str(temporary)
    bootstrap.verify_boot = allocation.verify_allocation
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-07', 'acceptance',
        'Combined E-025.18-23, PRE-M0 section 43 and R-011.14 bounded kernel-spine mechanisms, including AF-003/005/009, actual user fault survival, dynamic anonymous allocation, shared objects, live revocation, Job attribution and extended CPU context isolation. BSP user scheduling with actual AP startup/shared-work proof; fixed metadata and Internal scalar ABI. Root Supervisor/BAC reconstitution, synchronous typed RPC, general drivers/application loader and remote TLB shootdown remain later work. Clean-revision reproducibility is verified separately, never inferred from this dirty-tree mechanism gate.',
        sources, extra_checks=extra_checks))
