#!/usr/bin/env python3
"""Capability-enforced shared Memory Objects and backing-frame lifetime."""
import re
import sys
import bootstrap
import reclamation

RECORD = 'status=PASS objects=3 maps=6 denied=6 busy=3 destroyed=3 zeroed=true'


def verify_shared(evidence, runs, positive=True, cpus=1):
    records = reclamation.verify_reclamation(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_SHARED (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed shared Memory Object proof')
        if positive:
            records[index - 1]['reclamation']['shared_memory'] = True
            records[index - 1]['shared_memory'] = dict(objects=3, maps=6, denied=6,
                busy=3, destroyed=3, zeroed=True, cpu='BSP', public_allocator=False)
    return records


def extra_checks(run, checks):
    reclamation.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_shared(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_shared
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-02d', 'shared',
        'One-page Memory Objects with bounded mapping leases. Actual CPL3 map calls deny absent/insufficient authority, grant read-only mapping after capability IPC, and read peer-written shared bytes. Busy destruction rejects live mappings; quiescent backing is scrubbed and reclaimed. No public allocator, remote shootdown, live-map revocation or general heap.',
        sources, extra_checks=extra_checks))
