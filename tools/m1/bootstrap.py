#!/usr/bin/env python3
"""M1-01 acceptance: portable allocator tests and real boot/panic regressions.

Writes new evidence; never rewrites the frozen M0 acceptance. Existing ev build
and boot commands still use their development build/m0 artifact directory.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def verify_boot(evidence, expected_runs, bootstrap=True):
    result = json.loads((evidence / 'results.json').read_text())
    if not result['passed'] or len(result['runs']) != expected_runs:
        raise RuntimeError('Boot regression did not pass every requested run')
    records = []
    for run in result['runs']:
        serial = (evidence / run['directory'] / 'serial.log').read_text()
        matches = re.findall(
            r'^EVROSION_M1_BOOTSTRAP status=PASS page_size=(\d+) allocated=(\d+) '
            r'total=(\d+) remaining=(\d+) first=(0x[0-9a-f]+) second=(0x[0-9a-f]+)\r?$',
            serial, re.MULTILINE)
        if bootstrap:
            if len(matches) != 1:
                raise RuntimeError('Expected exactly one M1 bootstrap proof per boot')
            page, allocated, total, remaining = map(int, matches[0][:4])
            first, second = (int(value, 16) for value in matches[0][4:])
            if not (page == 4096 and allocated == 2 and total >= 2
                    and total - remaining == allocated and 0 < first < second < 1 << 52
                    and first % page == second % page == 0):
                raise RuntimeError('M1 bootstrap proof has invalid counts or frame addresses')
            records.append({'run': run['run'], 'total': total, 'remaining': remaining,
                            'first': first, 'second': second})
        elif matches:
            raise RuntimeError('Panic fixture unexpectedly reached the allocator smoke check')
    return records


def main(slice_id='M1-01', prefix='bootstrap',
         scope='Bootstrap frame selection only; no page mappings, reclamation, user isolation or complete M1 acceptance.',
         extra_sources=(), extra_checks=None):
    out = ROOT / 'build/m1/evidence' / f'{prefix}-{time.time_ns()}'
    out.mkdir(parents=True)
    checks = []
    result = {'schema': 1, 'slice': slice_id, 'passed': False, 'checks': checks, 'scope': scope}

    def run(name, command, expected_exit=0):
        log = out / (name + '.log')
        print(f'Checking {name} …', flush=True)
        with log.open('w') as output:
            process = subprocess.run(command, cwd=ROOT, stdout=output,
                                     stderr=subprocess.STDOUT, timeout=600)
        checks.append({'name': name, 'command': command, 'passed': process.returncode == expected_exit,
                       'expected_exit': expected_exit, 'actual_exit': process.returncode,
                       'log': str(log.relative_to(ROOT))})
        if process.returncode != expected_exit:
            raise RuntimeError(f'{name} failed ({process.returncode}); see {log.relative_to(ROOT)}')
        return log.read_text()

    def boot(name, args, count, bootstrap=True):
        text = run(name, ['cargo', 'ev', *args])
        paths = re.findall(r'^Evidence: (.+)$', text, re.MULTILINE)
        if len(paths) != 1:
            raise RuntimeError('Boot command did not identify its evidence')
        evidence = Path(paths[0]).resolve()
        if not evidence.is_relative_to(ROOT / 'build/m0/evidence'):
            raise RuntimeError('Boot evidence escaped the expected repository directory')
        checks[-1]['evidence'] = str((evidence / 'results.json').relative_to(ROOT))
        try:
            checks[-1]['bootstrap_records'] = verify_boot(evidence, count, bootstrap)
        except (RuntimeError, ValueError, KeyError, OSError):
            checks[-1]['passed'] = False
            raise

    try:
        for name, args in [
            ('allocator-host', ['cargo', 'test', '-p', 'ev-kernel', '--lib', '--locked', '--offline']),
            ('host-regression', ['cargo', 'test', '--locked', '--offline']),
            ('allocator-lint', ['cargo', 'clippy', '-p', 'ev-kernel', '--lib', '--tests', '--locked', '--offline', '--', '-D', 'warnings']),
            ('kernel-lint', ['cargo', 'clippy', '-p', 'ev-kernel', '--target', 'x86_64-unknown-none', '--all-features', '--locked', '--offline', '--', '-D', 'warnings']),
        ]:
            run(name, args)
        run('build', ['cargo', 'ev', 'build'])
        boot('boot', ['test', 'boot', '--runs', '3'], 3)
        run('panic-build', ['cargo', 'ev', 'build', '--fixture', 'panic'])
        boot('panic', ['test', 'panic'], 1, bootstrap=False)
        run('serial-only-build', ['cargo', 'ev', 'build', '--fixture', 'no-framebuffer'])
        boot('serial-only', ['test', 'boot', '--runs', '1'], 1)
        if extra_checks is not None:
            extra_checks(run, checks)
        run('restore-default-build', ['cargo', 'ev', 'build'])
        result['passed'] = True
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        result['error'] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        result['source_sha256'] = {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [ROOT / 'kernel/src/memory.rs', ROOT / 'kernel/src/lib.rs',
                         ROOT / 'kernel/src/main.rs', ROOT / 'libs/boot-contract/src/loader.rs',
                         ROOT / 'tools/ev/src/boot_protocol.rs', ROOT / 'tests/host/ev_boot.rs',
                         Path(__file__).resolve()] + [ROOT / p for p in extra_sources]
        }
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
        print(f'{"PASS" if result["passed"] else "FAIL"} {slice_id}: {out.relative_to(ROOT)}/results.json', flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
