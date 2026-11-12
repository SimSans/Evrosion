#!/usr/bin/env python3
"""Bounded capability table acceptance before userspace/custody integration."""
import re
import sys
import bootstrap
import preemption

RECORD = ('status=PASS scope=tables attenuation=true transfer=true '
          'revocation=true stale=true denial=true lifetime=true')


def verify_capabilities(evidence, runs, positive=True, cpus=1):
    records = preemption.verify_preemption(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_CAPS (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed capability table proof')
        if positive:
            records[index - 1]['capabilities'] = dict(scope='tables', attenuation=True,
                transfer=True, revocation=True, stale=True, denial=True, lifetime=True,
                userspace=False, custody=False)
    return records


def extra_checks(run, checks):
    preemption.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_capabilities(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_capabilities
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-05a', 'capabilities',
        'Internal bounded authority tables with attenuated rights, atomic handle move, retained lineage revocation and stale generation rejection. No userspace ABI, BAC, hardware object teardown or IPC transaction yet.',
        sources, extra_checks=extra_checks))
