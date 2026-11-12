#!/usr/bin/env python3
"""M2 measured authority-binding fixture plus complete cumulative M1 regression."""
import argparse
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/m1'))
import acceptance
import allocation
import bootstrap

RECORD = ('status=PASS scope=fixture grants=2 measured=true resolved=true '
          'atomic=true attenuated=true revoked=true')
LIFETIME = ('status=PASS scope=authority cycles=64 reclaimed=128 '
            'old_space_denied=true stale_handles_denied=true')

SCOPES = ('status=PASS scope=authority cycles=64 revoked=128 roots_preserved=true '
          'peers_preserved=true stale_revoke_denied=true')

INCARNATION = ('status=PASS scope=prepared bindings=2 held=true '
               'stale_events_denied=true limits=true revoked=true')
EXECUTABLE = ('status=PASS scope=loader segments=2 pages=5 frames=9 cpl3=5 '
              'measured=true zeroed=true wx=true guarded=true reclaimed=true')
ACTIVATION = ('status=PASS scope=fixture attempts=2 admitted=1 rejected=1 cpl3=1 '
              'rechecked=true stale_denied=true inhibited=true peers_preserved=true '
              'frames=18 reclaimed=true')
SUPERVISOR = ('status=PASS scope=bootstrap images=2 ready=2 faults=1 denied=4 '
              'readonly=true measured=true authority=true stopped=true reclaimed=true')
SERVICES = ('status=PASS scope=launch graphs=2 children=2 requests=5 replies=4 cancelled=1 faults=1 '
            'control_denied=8 service_denied=8 event_denied=6 delegated=4 observed=true '
            'held=true isolated=true measured=true reclaimed=true')
RPC = ('status=PASS scope=transport successes=7 accepted=8 blocks=8 wakes=8 denied=2 '
       'expired=2 timeouts=1 busy=true late=1 stale=true reclaimed=true')
RESTART = ('status=PASS scope=service cycles=64 faults=64 peer_replies=128 '
           'victim_replies=64 starts=66 stale=true root_preserved=true '
           'frames=true metadata=true reclaimed=true')

CUSTODY = 'status=PASS scope=graph incarnations=4 replacements=3 root_faults=4 graphs=4 service_starts=8 service_replies=8 accepted_transfers=4 rejected_transfers=4 invalidated_transfers=4 recovery=1 unique=true authority=true graph=true budget=true stale=true frames=true metadata=true independent=true'

RECOVERY_CASES='status=PASS scope=failure cases=11 faults=6 exits=4 watchdogs=4 interruptions=6 integrity=3 attempts=33 charged=24 held=20 admitted=16 active=15 graphs=14 starts=28 replies=28 transfers=14 rejected=14 invalidated=14 recovery=11 retired=true frames=true unique=true budget=true selection=true grants=true'

CAPRPC='status=PASS scope=transport worlds=5 accepted=8 blocks=8 wakes=8 delivered=6 returned=4 refunded=2 no_refund=2 timeouts=2 faults=2 late=1 stale=1 wrong_object=1 rejected=3 busy=true exits=5 frames=true metadata=true'

DISCIPLINE='status=PASS scope=threads worlds=2 calls=10 blocks=10 wakes=10 delivered=10 replies=10 contexts=10 spawned=6 exits=2 mutex_acquired=1 mutex_released=1 no_wait=1 cycles=1 extended=1 depth=1 wrong_thread=1 max_depth=8 stacks=true frames=true metadata=true'

def parse(serial, positive=True):
    lines = re.findall(r'^EVROSION_M2_BINDING (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([RECORD] if positive else []):
        raise ValueError('Missing, duplicate or malformed M2 authority-binding proof')
    lines = re.findall(r'^EVROSION_M2_LIFETIME (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([LIFETIME] if positive else []):
        raise ValueError('Missing, duplicate or malformed M2 authority-lifetime proof')
    lines = re.findall(r'^EVROSION_M2_SCOPES (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([SCOPES] if positive else []):
        raise ValueError('Missing, duplicate or malformed M2 authority-scope proof')
    lines = re.findall(r'^EVROSION_M2_INCARNATION (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([INCARNATION] if positive else []):
        raise ValueError('Missing, duplicate or malformed M2 incarnation proof')
    lines = re.findall(r'^EVROSION_M2_EXECUTABLE (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([EXECUTABLE] if positive else []):
        raise ValueError('Missing, duplicate or malformed M2 executable proof')
    lines = re.findall(r'^EVROSION_M2_ACTIVATION (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([ACTIVATION] if positive else []):
        raise ValueError('Missing, duplicate or malformed M2 activation proof')
    lines = re.findall(r'^EVROSION_M2_SUPERVISOR (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([SUPERVISOR] if positive else []):
        raise ValueError('Missing, duplicate or malformed supervisor bootstrap proof')
    lines = re.findall(r'^EVROSION_M2_SERVICES (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([SERVICES] if positive else []):
        raise ValueError('Missing, duplicate or malformed service launch proof')
    lines = re.findall(r'^EVROSION_M2_RPC (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([RPC] if positive else []):
        raise ValueError('Missing, duplicate or malformed synchronous RPC proof')
    lines = re.findall(r'^EVROSION_M2_RESTART (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([RESTART] if positive else []):
        raise ValueError('Missing, duplicate or malformed service restart proof')
    lines = re.findall(r'^EVROSION_M2_CUSTODY (.+)\r?$', serial, re.MULTILINE)
    if [line.strip() for line in lines] != ([CUSTODY] if positive else []):
        raise ValueError('Missing, duplicate or malformed custodian graph proof')
    lines=re.findall(r'^EVROSION_M2_RECOVERY_CASES (.+)\r?$',serial,re.MULTILINE)
    if [line.strip() for line in lines] != ([RECOVERY_CASES] if positive else []):
        raise ValueError('Missing, duplicate or malformed recovery failure proof')
    lines=re.findall(r'^EVROSION_M2_CAPRPC (.+)\r?$',serial,re.MULTILINE)
    if [line.strip() for line in lines] != ([CAPRPC] if positive else []):
        raise ValueError('Missing, duplicate or malformed capability RPC proof')
    lines=re.findall(r'^EVROSION_M2_IPC_DISCIPLINE (.+)\r?$',serial,re.MULTILINE)
    if [line.strip() for line in lines] != ([DISCIPLINE] if positive else []):
        raise ValueError('Missing, duplicate or malformed IPC discipline proof')


def verify(evidence, runs, positive=True, cpus=1):
    records = allocation.verify_allocation(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        parse((evidence / f'run-{index:03}/serial.log').read_text(), positive)
        if positive:
            records[index - 1]['bootstrap_binding'] = dict(
                scope='fixture', grants=2, measured=True, resolved=True,
                atomic=True, attenuated=True, revoked=True)
            records[index - 1]['authority_lifetime'] = dict(cycles=64, reclaimed=128,
                old_space_denied=True, stale_handles_denied=True)
            records[index - 1]['authority_scopes'] = dict(cycles=64, revoked=128,
                roots_preserved=True, peers_preserved=True, stale_revoke_denied=True)
            records[index - 1]['incarnation_binding'] = dict(scope='prepared', bindings=2,
                held=True, stale_events_denied=True, limits=True, revoked=True)
            records[index - 1]['executable_loading'] = dict(scope='loader',segments=2,pages=5,
                frames=9,cpl3=5,measured=True,zeroed=True,wx=True,guarded=True,reclaimed=True)
            records[index - 1]['incarnation_activation'] = dict(scope='fixture', attempts=2,
                admitted=1,rejected=1,cpl3=1,rechecked=True,stale_denied=True,
                inhibited=True,peers_preserved=True,frames=18,reclaimed=True)
            records[index - 1]['supervisor_bootstrap'] = dict(scope='bootstrap', images=2,
                ready=2,faults=1,denied=4,readonly=True,measured=True,authority=True,
                stopped=True,reclaimed=True)
            records[index - 1]['service_launch'] = dict(scope='launch',graphs=2,children=2,faults=1,
                requests=5,replies=4,cancelled=1,control_denied=8,service_denied=8,event_denied=6,delegated=4,observed=True,
                held=True,isolated=True,measured=True,reclaimed=True)
            records[index-1]['synchronous_rpc']=dict(scope='transport',successes=7,accepted=8,blocks=8,wakes=8,denied=2,expired=2,timeouts=1,busy=True,late=1,stale=True,reclaimed=True)
            records[index-1]['service_restart']=dict(scope='service',cycles=64,faults=64,peer_replies=128,victim_replies=64,starts=66,stale=True,root_preserved=True,frames=True,metadata=True,reclaimed=True)
            records[index-1]['custodian_graph']=dict(scope='graph',incarnations=4,replacements=3,root_faults=4,graphs=4,service_starts=8,service_replies=8,accepted_transfers=4,rejected_transfers=4,invalidated_transfers=4,recovery=1,unique=True,authority=True,graph=True,budget=True,stale=True,frames=True,metadata=True,independent=True)
            records[index-1]['recovery_failures']=dict(scope='failure',cases=11,faults=6,exits=4,watchdogs=4,interruptions=6,integrity=3,attempts=33,charged=24,held=20,admitted=16,active=15,graphs=14,starts=28,replies=28,transfers=14,rejected=14,invalidated=14,recovery=11,retired=True,frames=True,unique=True,budget=True,selection=True,grants=True)
            records[index-1]['capability_rpc']=dict(worlds=5,accepted=8,blocks=8,wakes=8,delivered=6,returned=4,refunded=2,no_refund=2,timeouts=2,faults=2,late=1,stale=1,wrong_object=1,rejected=3,busy=True,exits=5,frames=True,metadata=True)
            records[index-1]['ipc_discipline']=dict(worlds=2,calls=10,blocks=10,wakes=10,delivered=10,replies=10,contexts=10,spawned=6,exits=2,mutex_acquired=1,mutex_released=1,no_wait=1,cycles=1,extended=1,depth=1,wrong_thread=1,max_depth=8,stacks=True,frames=True,metadata=True)
    return records


def extra_checks(run, checks):
    acceptance.extra_checks(run, checks)
    run('m2-independent-fixture', ['python3', 'tools/m2/fixture.py'])
    run('m2-independent-executable', ['python3', 'tools/m2/executable_fixture.py'])
    run('m2-evidence-parser', ['python3', 'tools/m2/binding.py', '--self-test'])
    run('userspace-host', ['cargo', 'test', '-p', 'ev-userspace-contract', '-p', 'ev-root-supervisor', '--locked', '--offline'])
    run('echo-host', ['cargo','test','-p','ev-echo-service','-p','ev-userspace-runtime','--locked','--offline'])
    run('generated-idl', ['python3','tools/idl/generate.py','--check'])
    run('generated-block-idl', ['python3','tools/idl/generate_block.py','--check'])
    run('idl-producer-tests', ['python3','-m','unittest','discover','-s','tools/idl','-v'])
    run('userspace-lint', ['cargo', 'clippy', '-p', 'ev-userspace-contract', '-p', 'ev-root-supervisor', '--lib', '--tests', '--locked', '--offline', '--', '-D', 'warnings'])
    for name, feature in [('supervisor-lint', 'executable'), ('supervisor-fault-lint', 'test-fault'), ('supervisor-service-fault-lint','service-fault'), ('supervisor-rpc-lint','service-rpc'), ('supervisor-rpc-timeout-lint','service-rpc-timeout'), ('supervisor-restart-lint','service-restart'), ('supervisor-custody-lint','custody-graph'), ('supervisor-exit-lint','custody-exit'), ('supervisor-watchdog-lint','custody-watchdog')]:
        run(name, ['cargo', 'clippy', '-p', 'ev-root-supervisor', '--release', '--target', 'x86_64-unknown-none', '--features', feature, '--locked', '--offline', '--', '-D', 'warnings'])
    run('supervisor-launch-lint',['cargo','clippy','-p','ev-root-supervisor','--release','--target','x86_64-unknown-none','--features','service-launch','--locked','--offline','--','-D','warnings'])
    run('echo-lint',['cargo','clippy','-p','ev-echo-service','--release','--target','x86_64-unknown-none','--all-features','--locked','--offline','--','-D','warnings'])
    run('recovery-host',['cargo','test','-p','ev-recovery-service','--locked','--offline'])
    run('cap-actors-host',['cargo','test','-p','ev-cap-client','-p','ev-cap-server','--locked','--offline'])
    run('discipline-host',['cargo','test','-p','ev-ipc-discipline','--locked','--offline'])
    for feature in ['executable','depth']:
        run('discipline-'+feature+'-lint',['cargo','clippy','-p','ev-ipc-discipline','--release','--target','x86_64-unknown-none','--features',feature,'--locked','--offline','--','-D','warnings'])
    for package,features in [('ev-cap-client',['executable','test-timeout','test-death','test-queued-timeout','test-queued-death']),('ev-cap-server',['executable','test-delay','test-fault','test-hold','test-queued-fault'])]:
        for feature in features:
            run(package+'-'+feature+'-lint',['cargo','clippy','-p',package,'--release','--target','x86_64-unknown-none','--features',feature,'--locked','--offline','--','-D','warnings'])
    run('recovery-lint',['cargo','clippy','-p','ev-recovery-service','--release','--target','x86_64-unknown-none','--features','executable','--locked','--offline','--','-D','warnings'])
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify((ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


def self_test():
    valid = 'EVROSION_M2_BINDING ' + RECORD + '\nEVROSION_M2_LIFETIME ' + LIFETIME + '\nEVROSION_M2_SCOPES ' + SCOPES + '\nEVROSION_M2_INCARNATION ' + INCARNATION + '\nEVROSION_M2_EXECUTABLE ' + EXECUTABLE + '\nEVROSION_M2_ACTIVATION ' + ACTIVATION + '\nEVROSION_M2_SUPERVISOR ' + SUPERVISOR + '\n'
    valid += 'EVROSION_M2_SERVICES ' + SERVICES + '\nEVROSION_M2_RPC ' + RPC + '\n'
    valid += 'EVROSION_M2_RESTART ' + RESTART + '\n'
    valid += 'EVROSION_M2_CUSTODY ' + CUSTODY + '\n'
    valid += 'EVROSION_M2_RECOVERY_CASES ' + RECOVERY_CASES + '\n'
    valid += 'EVROSION_M2_CAPRPC ' + CAPRPC + '\n'
    valid += 'EVROSION_M2_IPC_DISCIPLINE ' + DISCIPLINE + '\n'
    parse(valid)
    parse('', False)
    for invalid in ['', valid * 2, valid.replace('grants=2', 'grants=1'),
                    valid.replace('resolved=true', 'resolved=false'),
                    valid.replace('scope=fixture', 'scope=supervisor'),
                    valid.replace('cycles=64', 'cycles=1'),
                    valid.replace('reclaimed=128', 'reclaimed=0'),
                    valid.split('EVROSION_M2_LIFETIME')[0],
                    valid.split('EVROSION_M2_SCOPES')[0],
                    valid.replace('revoked=128', 'revoked=0'),
                    valid.replace('roots_preserved=true', 'roots_preserved=false'),
                    valid.replace('stale_revoke_denied=true', 'stale_revoke_denied=false'),
                    valid.split('EVROSION_M2_INCARNATION')[0],
                    valid.replace('scope=prepared', 'scope=active'),
                    valid.replace('held=true', 'held=false'),
                    valid.replace('stale_events_denied=true', 'stale_events_denied=false'),
                    valid.split('EVROSION_M2_EXECUTABLE')[0],
                    valid.replace('scope=loader','scope=supervisor'),
                    valid.replace('cpl3=5','cpl3=0'),
                    valid.replace('wx=true','wx=false'),
                    valid.replace('reclaimed=true','reclaimed=false'),
                    valid.split('EVROSION_M2_ACTIVATION')[0],
                    valid.replace('admitted=1','admitted=2'),
                    valid.replace('rechecked=true','rechecked=false'),
                    valid.replace('inhibited=true','inhibited=false'),
                    valid.split('EVROSION_M2_SUPERVISOR')[0],
                    valid.replace('ready=2','ready=0'),
                    valid.replace('faults=1','faults=0'),
                    valid.replace('readonly=true','readonly=false'),
                    valid.split('EVROSION_M2_SERVICES')[0],
                    valid.replace('children=2','children=0'),
                    valid.replace('replies=4','replies=0'),
                    valid.replace('delegated=4','delegated=0'),
                    valid.split('EVROSION_M2_RPC')[0],
                    valid.replace('blocks=8','blocks=0'),
                    valid.replace('late=1','late=0'),
                    valid.split('EVROSION_M2_RESTART')[0],
                    valid.replace('peer_replies=128','peer_replies=0'),
                    valid.replace('metadata=true','metadata=false'),
                    valid.replace('root_preserved=true','root_preserved=false'),
                    valid.split('EVROSION_M2_CUSTODY')[0],
                    valid.replace('independent=true','independent=false'),
                    valid.replace('invalidated_transfers=4','invalidated_transfers=0'),
                    valid.split('EVROSION_M2_RECOVERY_CASES')[0],
                    valid.replace('selection=true','selection=false'),
                    valid.replace('charged=24','charged=0'),
                    valid.split('EVROSION_M2_CAPRPC')[0],
                    valid.replace('wrong_object=1','wrong_object=0'),
                    valid.replace('refunded=2','refunded=0'),
                    valid.split('EVROSION_M2_IPC_DISCIPLINE')[0],
                    valid.replace('no_wait=1','no_wait=0'),
                    valid.replace('stacks=true','stacks=false')]:
        try:
            parse(invalid)
        except ValueError:
            continue
        raise RuntimeError('Evidence parser accepted invalid proof')
    try:
        parse(valid, False)
    except ValueError:
        print('PASS: M2 evidence parser positive/negative cases')
        return
    raise RuntimeError('Panic fixture accepted an unexpected binding proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        temporary = ROOT / 'build/test-tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        os.environ['TMPDIR'] = str(temporary)
        bootstrap.verify_boot = verify
        sources = [str(p.relative_to(ROOT)) for folder in ['kernel/src', 'kernel/fixtures', 'tools/m1', 'tools/m2', 'libs', 'services', 'idl', 'tools/idl']
                   for p in sorted((ROOT / folder).rglob('*')) if p.is_file() and '__pycache__' not in p.parts]
        sources += ['kernel/Cargo.toml', 'kernel/build.rs', 'Cargo.toml', 'Cargo.lock',
                    'tools/ev/Cargo.toml', 'tools/ev/src/supervisor.rs',
                    'tools/ev/src/build.rs', 'tools/ev/src/boot.rs', 'tools/ev/src/cli.rs']
        sys.exit(bootstrap.main('M2-01', 'm2-binding',
            'Combined bounded M2 capability-native userspace engineering gate (E025.25-33/R011.15) with the complete cumulative M1 regression. '
            'Actual source-built Rust Root creates isolated services/Jobs/channels, delegates exact measured authority and executes generated typed IPC. '
            'Proves executable W^X/guards/ownership, capability denial/attenuation/transfer, generation-safe retirement and64 ordinary service replacements with128 unrelated peer replies. '
            'Proves whole Root graph revocation/exact reconstruction, accepted-before-revocation capability invalidation, charged restart exhaustion and independent measured recovery. '
            'Eleven real failure worlds cover fatal exits, independently confirmed watchdogs, six interrupted replacement stages and corrupt manifest/image/authority selection. '
            'Five actual capability-RPC worlds prove transactional ownership, queued refunds, delivered no-refund failures, real receiver faults and late/stale/wrong-object isolation. '
            'Generated client held under a real Mutex lease is denied; separate-process A-B-C forwarding inherits protected deadline/origin, with ancestor/extension rejection. '
            'Nine actual threads in three isolated processes execute depth8 and reject attempt9 before ancestor/capacity checks, without increasing metadata bounds. '
            'Timeout proof preserves distinct-value late isolation and explicitly retries the identical declared READ_ONLY operation. '
            'BSP userspace with actual parked-AP startup evidence, finite Internal profiles and no device/DMA grants. '
            'Does not claim general mutating exactly-once/durable retry, production boot authentication, persistent generations, SMP user scheduling or a consumer release.',
            sources, extra_checks=extra_checks))
