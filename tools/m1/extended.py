#!/usr/bin/env python3
"""Eager legacy extended CPU contexts and saved-state corruption detection."""
import json
from pathlib import Path
import re
import sys
import bootstrap
import json
from pathlib import Path
import revocation

RECORD = 'status=PASS processes=6 x87=true xmm=true mxcsr=true clean=true eager=true'


def verify_extended(evidence, runs, positive=True, cpus=1):
    records = revocation.verify_revocation(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_FX (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed extended context proof')
        if positive:
            records[index - 1]['extended_context'] = dict(processes=6, x87=True, xmm=True, mxcsr=True, clean=True, eager=True)
    return records


def extra_checks(run, checks):
    revocation.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_extended(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True
    run('fx-corruption-build', ['cargo', 'ev', 'build', '--fixture', 'fx-corruption'])
    output = run('fx-corruption', ['cargo', 'ev', 'test', 'boot', '--runs', '1'], expected_exit=1)
    checks[-1]['passed'] = False
    paths = re.findall(r'^Evidence: (.+)$', output, re.MULTILINE)
    if len(paths) != 1:
        raise RuntimeError('Missing extended context negative evidence')
    evidence = Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT / 'build/m0/evidence'):
        raise RuntimeError('Evidence escaped repository')
    result = json.loads((evidence / 'results.json').read_text())
    serial = (evidence / 'run-001/serial.log').read_text()
    if (result['passed'] or len(result['runs']) != 1 or result['runs'][0]['exit_status'] != 35
            or serial.count('user register/state fixture failed') != 1
            or 'EVROSION_M1_FX status=PASS' in serial
            or serial.count('EVROSION_M0_RESULT status=FAIL code=1') != 1):
        raise RuntimeError('Corrupted XMM context was not detected by actual userspace')
    checks[-1].update(passed=True, evidence=str((evidence / 'results.json').relative_to(bootstrap.ROOT)),
        expected_failure='User detects corrupted XMM0 after preemption; finite kernel proof failure, exit 35')


if __name__ == '__main__':
    bootstrap.verify_boot = verify_extended
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-04e', 'extended',
        'Eager x87/MMX/XMM/MXCSR isolation across every scheduled user trap, clean initial images, real per-process register sentinels and injected saved-XMM corruption rejection. XSAVE/AVX and user FS/GS-base writes remain disabled; no TLS ABI.',
        sources, extra_checks=extra_checks))
