#!/usr/bin/env python3
"""Firmware topology acceptance; enumeration alone never claims AP execution."""
import re
import sys
import json
from pathlib import Path
import bootstrap
import faults
import timer


def verify_topology(evidence, runs, positive=True, cpus=1):
    records = timer.verify_timer(evidence, runs, positive)
    result = json.loads((evidence / 'results.json').read_text())
    if result['cpus'] != cpus:
        raise RuntimeError('QEMU CPU count differs from requested topology fixture')
    for index in range(1, runs+1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        matches = re.findall(r'^EVROSION_M1_TOPOLOGY status=PASS enabled=(\d+) bsp=(\d+) '
                             r'lapic=(0x[0-9a-f]+)\r?$', serial, re.MULTILINE)
        if len(matches) != (1 if positive else 0):
            raise RuntimeError('Missing, duplicate or unexpected topology proof')
        if positive:
            count, bsp = map(int,matches[0][:2]); lapic=int(matches[0][2],16)
            if count != cpus or not 0 <= bsp <= 0xffffffff or not 0 < lapic < 1 << 52 or lapic % 4096:
                raise RuntimeError('Firmware topology does not match QEMU CPU configuration')
            records[index-1]['topology']={'cpus':count,'bsp':bsp,'lapic':lapic,'ap_execution':False}
    return records


def two_cpu_and_negative(run, checks):
    run('two-cpu-build',['cargo','ev','build'])
    text=run('two-cpu-topology',['cargo','ev','test','boot','--cpus','2','--runs','3'])
    checks[-1]['passed']=False
    paths=re.findall(r'^Evidence: (.+)$',text,re.MULTILINE)
    if len(paths)!=1: raise RuntimeError('Two-CPU fixture did not identify evidence')
    evidence=Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT/'build/m0/evidence'): raise RuntimeError('Evidence escaped repository')
    records=verify_topology(evidence,3,cpus=2)
    checks[-1].update(passed=True,evidence=str((evidence/'results.json').relative_to(bootstrap.ROOT)),bootstrap_records=records)
    faults.unexpected_exception(run,checks)


if __name__=='__main__':
    bootstrap.verify_boot=verify_topology
    sys.exit(bootstrap.main('M1-03c.1','topology',
        'Bounded firmware CPU enumeration under one/two-CPU QEMU. AP startup, per-CPU state, APIC routing and synchronization remain pending.',
        ['kernel/src/mapping.rs','kernel/src/paging.rs','kernel/src/exception.rs',
         'kernel/src/traps.rs','kernel/src/traps.S','kernel/src/user.rs',
         'kernel/src/user_space.rs','kernel/src/user.S','kernel/src/time.rs',
         'kernel/src/timer.rs','kernel/src/acpi.rs','kernel/src/firmware.rs',
         'kernel/Cargo.toml','libs/boot-contract/src/lib.rs','tools/ev/src/cli.rs',
         'tools/ev/src/build.rs','tools/ev/src/boot.rs','tools/m1/paging.py','tools/m1/faults.py',
         'tools/m1/user.py','tools/m1/timer.py','tools/m1/topology.py'],extra_checks=two_cpu_and_negative))
