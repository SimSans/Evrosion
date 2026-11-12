#!/usr/bin/env python3
"""Runtime anonymous allocation, scrubbed reuse and exact freed-address faults."""
import re
import sys
import bootstrap
import fault_delivery

RECORD = 'status=PASS allocated=6 freed=6 denied=3 zeroed=true unmapped=true rollback=true'


def verify_allocation(evidence, runs, positive=True, cpus=1):
    records = fault_delivery.verify_fault_delivery(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_ALLOC (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed anonymous allocation proof')
        if positive:
            records[index - 1]['allocation'] = dict(allocated=6, freed=6, denied=3, zeroed=True, unmapped=True, rollback=True)
            if records[index - 1]['jobs']['frames'] != 51:
                raise RuntimeError('Anonymous frames missing from Job attribution')
    return records


def extra_checks(run, checks):
    fault_delivery.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_allocation(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_allocation
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-02e', 'allocation',
        'Capability-bound, Job-charged anonymous Memory Object allocation/free after bootstrap. Six real user allocation cycles verify whole-page zeroing, stale free rejection and exact freed-address CPL3 faults. Host proofs cover authority, budget, physical exhaustion, descriptor/table failure and rollback. Bounded retained metadata; no general heap or memory-policy service.',
        sources, extra_checks=extra_checks))
