#!/usr/bin/env python3
"""Executed two-CPU startup, shared atomic work and deliberate stalled handshake."""
import re
import sys
import json
from pathlib import Path
import bootstrap
import topology


def verify_smp(evidence,runs,positive=True,cpus=1):
    records=topology.verify_topology(evidence,runs,positive,cpus)
    for index in range(1,runs+1):
        serial=(evidence/f'run-{index:03}/serial.log').read_text()
        lines=re.findall(r'^EVROSION_M1_SMP (.+)\r?$',serial,re.MULTILINE)
        if len(lines)!=(1 if positive else 0): raise RuntimeError('Missing/duplicate/unexpected SMP record')
        if not positive: continue
        if cpus==1:
            if lines[0].strip()!='status=SKIP reason=single_cpu': raise RuntimeError('Single CPU must explicitly skip SMP proof')
            records[index-1]['smp']={'status':'SKIP','online':1}
        else:
            match=re.fullmatch(r'status=PASS online=2 ap=(\d+) root=(0x[0-9a-f]+) shared=20000 parked=true',lines[0].strip())
            if not match: raise RuntimeError('Incomplete actual SMP execution proof')
            ap=int(match[1]);root=int(match[2],16)
            if ap==records[index-1]['topology']['bsp'] or not 0<=ap<255 or not 0<root<1<<32 or root%4096:
                raise RuntimeError('Invalid AP identity/root')
            records[index-1]['smp']={'status':'PASS','online':2,'ap':ap,'root':root,'shared':20000,'parked':True}
    return records


def extra_checks(run,checks):
    topology.two_cpu_and_negative(run,checks)
    for check in checks:
        if check['name']=='two-cpu-topology':
            check['passed']=False
            check['bootstrap_records']=verify_smp((bootstrap.ROOT/check['evidence']).parent,3,cpus=2)
            check['passed']=True
    run('ap-timeout-build',['cargo','ev','build','--fixture','ap-timeout'])
    text=run('ap-timeout',['cargo','ev','test','boot','--runs','1','--cpus','2'],expected_exit=1)
    checks[-1]['passed']=False
    paths=re.findall(r'^Evidence: (.+)$',text,re.MULTILINE)
    if len(paths)!=1: raise RuntimeError('AP timeout fixture did not identify evidence')
    evidence=Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT/'build/m0/evidence'): raise RuntimeError('Evidence escaped repository')
    result=json.loads((evidence/'results.json').read_text());serial=(evidence/'run-001/serial.log').read_text()
    if (result['passed'] or result['cpus']!=2 or len(result['runs'])!=1 or result['runs'][0]['exit_status']!=35
        or serial.count('message=M1 deliberate withheld AP command: bounded AP failure observed')!=1
        or serial.count('EVROSION_PANIC ')!=1 or 'EVROSION_M1_SMP status=PASS' in serial
        or serial.count('EVROSION_M0_RESULT status=FAIL code=1')!=1 or 'EVROSION_M0_RESULT status=PASS' in serial):
        raise RuntimeError('Withheld-command fixture did not prove bounded AP failure')
    checks[-1].update(passed=True,evidence=str((evidence/'results.json').relative_to(bootstrap.ROOT)),
                      expected_failure='AP became ready, withheld command exhausted its finite wait, BSP observed failure and exited 35')


if __name__=='__main__':
    bootstrap.verify_boot=verify_smp
    sys.exit(bootstrap.main('M1-03c.2','smp',
        'One xAPIC AP executes on its owned root/stack, completes shared atomic work and parks; withheld-command failure bounded. No SMP scheduling/IRQ recovery/TLB shootdown.',
        ['kernel/src/mapping.rs','kernel/src/paging.rs','kernel/src/exception.rs',
         'kernel/src/traps.rs','kernel/src/traps.S','kernel/src/user.rs',
         'kernel/src/user_space.rs','kernel/src/user.S','kernel/src/time.rs',
         'kernel/src/timer.rs','kernel/src/acpi.rs','kernel/src/firmware.rs','kernel/src/smp.rs','kernel/src/ap.S',
         'kernel/Cargo.toml','libs/boot-contract/src/lib.rs','tools/ev/src/cli.rs',
         'tools/ev/src/build.rs','tools/ev/src/boot.rs','tools/m1/paging.py','tools/m1/faults.py',
         'tools/m1/user.py','tools/m1/timer.py','tools/m1/topology.py','tools/m1/smp.py'],extra_checks=extra_checks))
