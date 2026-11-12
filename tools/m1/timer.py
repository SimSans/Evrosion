#!/usr/bin/env python3
"""Bootstrap interrupt clock/deadline proof and all preceding M1 regressions."""
import re
import sys
import bootstrap
import faults
import user


def verify_timer(evidence, runs, positive=True):
    records = user.verify_user(evidence, runs, positive)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        matches = re.findall(r'^EVROSION_M1_TIMER status=PASS ticks=(\d+) deadline=8 '
                             r'masked_bound=true interrupts_off=true\r?$', serial, re.MULTILINE)
        if len(matches) != (1 if positive else 0):
            raise RuntimeError('Missing, duplicate or unexpected timer proof')
        if positive:
            ticks = int(matches[0])
            if not 8 <= ticks <= 64:
                raise RuntimeError('Timer failed to meet the bounded tick deadline')
            records[index-1]['timer'] = {'ticks': ticks, 'deadline': 8,
                'masked_bound': True, 'interrupts_off': True}
    return records


if __name__ == '__main__':
    bootstrap.verify_boot = verify_timer
    sys.exit(bootstrap.main('M1-03b', 'timer',
        'Bootstrap PIC/PIT IRQ clock and bounded monotonic tick deadlines. APIC/SMP, preemption, general routing and IPC deadlines remain pending.',
        ['kernel/src/mapping.rs', 'kernel/src/paging.rs', 'kernel/src/exception.rs',
         'kernel/src/traps.rs', 'kernel/src/traps.S', 'kernel/src/user.rs',
         'kernel/src/user_space.rs', 'kernel/src/user.S', 'kernel/src/time.rs',
         'kernel/src/timer.rs', 'kernel/Cargo.toml', 'tools/ev/src/cli.rs',
         'tools/ev/src/build.rs', 'tools/m1/paging.py', 'tools/m1/faults.py',
         'tools/m1/user.py', 'tools/m1/timer.py'], extra_checks=faults.unexpected_exception))
