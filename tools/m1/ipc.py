#!/usr/bin/env python3
"""Bounded asynchronous mailbox and capability-escrow acceptance."""
import re
import sys
import bootstrap
import capabilities

RECORD = ('status=PASS scope=mailbox bounded=true escrow=true delivery=true '
          'deadline=true death_return=true')


def verify_ipc(evidence, runs, positive=True, cpus=1):
    records = capabilities.verify_capabilities(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_IPC (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed mailbox proof')
        if positive:
            records[index - 1]['ipc'] = dict(scope='mailbox', bounded=True, escrow=True,
                delivery=True, deadline=True, death_return=True, userspace=False,
                scheduler_wait_queue=False)
    return records


def extra_checks(run, checks):
    capabilities.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_ipc(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_ipc
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-06a', 'ipc',
        'Bounded asynchronous mailbox with capability escrow, atomic acceptance/delivery, absolute expiry and sender reclamation after expiry or receiver-death notification. No scheduled userspace, synchronous RPC, syscall decoding or general fault delivery.',
        sources, extra_checks=extra_checks))
