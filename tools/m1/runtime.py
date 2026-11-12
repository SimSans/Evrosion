#!/usr/bin/env python3
"""Scheduled CPL3, scalar capability IPC and process-fault containment proof."""
import json
import re
import sys
from pathlib import Path
import bootstrap
import ipc


def verify_runtime(evidence, runs, positive=True, cpus=1):
    records = ipc.verify_ipc(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_RUNTIME (.+)\r?$', serial, re.MULTILINE)
        if len(lines) != (1 if positive else 0):
            raise RuntimeError('Missing, duplicate or unexpected user runtime proof')
        if not positive:
            continue
        match = re.fullmatch(r'status=PASS processes=6 faults=3 survivors=3 messages=3 '
                             r'quanta=(\d+) isolated=true authority=true restored=true',
                             lines[0].strip())
        if not match or not 12 <= int(match[1]) <= 3072:
            raise RuntimeError('Invalid user runtime counts or authority/containment proof')
        records[index - 1]['user_runtime'] = dict(processes=6, faults=3, survivors=3,
            messages=3, quanta=int(match[1]), isolated=True, authority=True,
            restored=True, fault_vectors=[6, 14, 13], cpu='BSP', scalar_ipc=True,
            scheduler_wait_queue_verified=False, public_abi=False)
    return records


def extra_checks(run, checks):
    ipc.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_runtime(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True
    run('runtime-kernel-fault-build', ['cargo', 'ev', 'build', '--fixture', 'runtime-kernel-fault'])
    text = run('runtime-kernel-fault', ['cargo', 'ev', 'test', 'boot', '--runs', '1'], expected_exit=1)
    checks[-1]['passed'] = False
    paths = re.findall(r'^Evidence: (.+)$', text, re.MULTILINE)
    if len(paths) != 1:
        raise RuntimeError('Runtime kernel-fault fixture did not identify evidence')
    evidence = Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT / 'build/m0/evidence'):
        raise RuntimeError('Evidence escaped repository')
    result = json.loads((evidence / 'results.json').read_text())
    serial = (evidence / 'run-001/serial.log').read_text()
    if (result['passed'] or len(result['runs']) != 1 or result['runs'][0]['exit_status'] != 35
            or len(re.findall(r'^EVROSION_EXCEPTION vector=6 error=0x0 rip=0x[0-9a-f]+ '
                              r'address=0x[0-9a-f]+\r?$', serial, re.MULTILINE)) != 1
            or serial.count('EVROSION_M1_IPC status=PASS') != 1
            or 'EVROSION_M1_RUNTIME status=PASS' in serial
            or serial.count('EVROSION_M0_RESULT status=FAIL code=1') != 1
            or 'EVROSION_M0_RESULT status=PASS' in serial):
        raise RuntimeError('Kernel fault during user scheduling was not fatal')
    checks[-1].update(passed=True, evidence=str((evidence / 'results.json').relative_to(bootstrap.ROOT)),
        expected_failure='CPL0 #UD with runtime active remains fatal; vector 6 and QEMU exit 35')


if __name__ == '__main__':
    bootstrap.verify_boot = verify_runtime
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-06b', 'runtime',
        'BSP timer-preempted private CPL3 contexts, kernel-selected caller identity, scalar capability IPC and surviving peers after UD/PF/GP. CPL0 faults stay fatal. Retained frames; this suite does not verify wait queues, sync RPC, resource reclamation, public ABI or service supervision.',
        sources, extra_checks=extra_checks))
