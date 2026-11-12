#!/usr/bin/env python3
"""Hierarchical Job resource admission and scheduled-user attribution."""
import re
import sys
import bootstrap
import shared


def verify_jobs(evidence, runs, positive=True, cpus=1):
    records = shared.verify_shared(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_JOBS (.+)\r?$', serial, re.MULTILINE)
        if len(lines) != (1 if positive else 0):
            raise RuntimeError('Missing, duplicate or unexpected Job resource proof')
        if not positive:
            continue
        match = re.fullmatch(r'status=PASS jobs=9 frames=(45|51) cpu_ticks=(\d+) '
                             r'hierarchy=true admission=true live_zero=true', lines[0].strip())
        if not match or int(match[2]) != records[index - 1]['user_runtime']['quanta']:
            raise RuntimeError('Job attribution does not match scheduled user ticks')
        records[index - 1]['jobs'] = dict(jobs=9, frames=int(match[1]), cpu_ticks=int(match[2]),
            hierarchy=True, admission=True, live_zero=True, cpu='BSP', wall_time=False)
    return records


def extra_checks(run, checks):
    shared.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_jobs(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_jobs
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-04d', 'jobs',
        'Canonical scheduler Jobs enforce independent process/thread/frame and sampled CPU-tick limits through bounded ancestry, with atomic admission and balanced release. Real CPL3 timer ticks match owning/ancestor Job charges; private/shared frames remain charged until quiescent release. No elapsed CPU time, replenishing CPU quotas, storage/device budgets or public allocator.',
        sources, extra_checks=extra_checks))
