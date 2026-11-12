#!/usr/bin/env python3
"""Scheduled-user IPC arrival/timeout wake and finite idle-clock failure."""
import json
import re
import sys
from pathlib import Path
import bootstrap
import runtime


def verify_waits(evidence, runs, positive=True, cpus=1):
    records = runtime.verify_runtime(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_WAITS (.+)\r?$', serial, re.MULTILINE)
        if len(lines) != (1 if positive else 0):
            raise RuntimeError('Missing, duplicate or unexpected user wait proof')
        if not positive:
            continue
        match = re.fullmatch(r'status=PASS blocks=6 signals=3 deadlines=3 '
                             r'idle_ticks=(\d+) retired=true', lines[0].strip())
        if not match or not 3 <= int(match[1]) <= 3072:
            raise RuntimeError('Invalid user wait counts or stale-registration proof')
        records[index - 1]['user_runtime']['scheduler_wait_queue_verified'] = True
        records[index - 1]['user_waits'] = dict(blocks=6, signals=3, deadlines=3,
            idle_ticks=int(match[1]), retired=True, cpu='BSP', public_abi=False)
    return records


def extra_checks(run, checks):
    runtime.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_waits(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True
    run('user-wait-stall-build', ['cargo', 'ev', 'build', '--fixture', 'user-wait-stall'])
    text = run('user-wait-stall', ['cargo', 'ev', 'test', 'boot', '--runs', '1'], expected_exit=1)
    checks[-1]['passed'] = False
    paths = re.findall(r'^Evidence: (.+)$', text, re.MULTILINE)
    if len(paths) != 1:
        raise RuntimeError('Idle-clock fixture did not identify evidence')
    evidence = Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT / 'build/m0/evidence'):
        raise RuntimeError('Evidence escaped repository')
    result = json.loads((evidence / 'results.json').read_text())
    serial = (evidence / 'run-001/serial.log').read_text()
    if (result['passed'] or len(result['runs']) != 1 or result['runs'][0]['exit_status'] != 35
            or serial.count('message=user wait clock stalled within finite idle bound') != 1
            or serial.count('EVROSION_PANIC ') != 1
            or serial.count('EVROSION_M1_IPC status=PASS') != 1
            or 'EVROSION_M1_RUNTIME status=PASS' in serial
            or 'EVROSION_M1_WAITS status=PASS' in serial
            or serial.count('EVROSION_M0_RESULT status=FAIL code=1') != 1
            or 'EVROSION_M0_RESULT status=PASS' in serial):
        raise RuntimeError('Stopped idle clock did not fail within its finite poll bound')
    checks[-1].update(passed=True, evidence=str((evidence / 'results.json').relative_to(bootstrap.ROOT)),
        expected_failure='Masked IRQ0 during blocked user receive exhausts 4096 polls; QEMU exits 35')


if __name__ == '__main__':
    bootstrap.verify_boot = verify_waits
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-06c', 'waits',
        'Serialized BSP receive predicate/enrollment and arrival/absolute-deadline wake for private CPL3 processes. Bounded FIFO registrations retire stale tickets; idle clock failure is finite. No general process teardown, fault subscriptions, sync RPC, resource budgets or public ABI.',
        sources, extra_checks=extra_checks))
