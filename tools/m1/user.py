#!/usr/bin/env python3
"""Real CPL3 address-space isolation with cumulative M1 regression evidence."""
import re
import sys
import bootstrap
import faults


def verify_user(evidence, runs, positive=True):
    records = faults.verify_faults(evidence, runs, positive)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        matches = re.findall(r'^EVROSION_M1_USER status=PASS roots=2 cpl=3 private=true '
            r'kernel_denied=true wx=true stack=true io_denied=true traps=15 '
            r'root_a=(0x[0-9a-f]+) root_b=(0x[0-9a-f]+)\r?$', serial, re.MULTILINE)
        if len(matches) != (1 if positive else 0):
            raise RuntimeError('Missing, duplicate or unexpected user isolation proof')
        if positive:
            a, b = (int(value, 16) for value in matches[0])
            if a == b or any(root == 0 or root >= 1 << 52 or root % 4096 for root in (a,b)):
                raise RuntimeError('Invalid user root addresses')
            records[index-1]['user'] = {'cpl': 3, 'roots': [a,b], 'traps': 15,
                'private': True, 'kernel_denied': True, 'wx': True, 'stack': True, 'io_denied': True}
    return records


if __name__ == '__main__':
    bootstrap.verify_boot = verify_user
    sys.exit(bootstrap.main('M1-02b', 'user',
        'Owned CPL3 bootstrap roots and exact isolation fixtures. General process/scheduler fault containment, reclamation, capabilities and SMP remain pending.',
        ['kernel/src/mapping.rs', 'kernel/src/paging.rs', 'kernel/src/exception.rs',
         'kernel/src/traps.rs', 'kernel/src/traps.S', 'kernel/src/user.rs',
         'kernel/src/user_space.rs', 'kernel/src/user.S', 'kernel/Cargo.toml',
         'tools/ev/src/cli.rs', 'tools/ev/src/build.rs', 'tools/m1/paging.py',
         'tools/m1/faults.py', 'tools/m1/user.py'], extra_checks=faults.unexpected_exception))
