#!/usr/bin/env python3
"""Cumulative M3 persistence SUBSET; this is never whole-M3 acceptance.

Default: validate retained PIO/journal/fault+progress/File/owner experiments without
rerunning them. Each workflow accepts an exact retained evidence path; repeat
--owner-resume for actual live-stdin cancel and continue receipts. --fresh KIND runs only that owned workflow again.
All cumulative M1/M2 checks still execute. Keep active code frozen throughout.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def workspace():
    for path in Path(__file__).resolve().parents:
        if (path / 'Cargo.toml').is_file() and (path / 'kernel/src').is_dir():
            return path
    raise RuntimeError('M3 validator must run within its Evrosion repository')


ROOT = workspace()
sys.path.insert(0, str(ROOT / 'tools/m2'))
import binding
bootstrap = binding.bootstrap
SECTOR = 512
DISK_BYTES = 8192 * SECTOR
NAMES = {'pio': 'storage-pio', 'journal': 'storage-journal', 'generation': 'generation',
         'file': 'storage-file', 'progress': 'generation-progress', 'owner': 'owner-recovery'}
SOURCE_SCOPE = ('All existing non-document Git sources, excluding docs/, architecture/, '
                'project/, LICENSES/, tools/m3/ and Markdown/text documents. tools/m3 is '
                'validation code recorded separately, not a compiled guest input. '
                'Retained full manifests remain unchanged; full-tree fingerprints may '
                'differ after documentation/validator-only edits.')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(64 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def passed(record):
    errors = ('error', 'capture_error', 'seal_error', 'validation_error', 'boot_link_error')
    return record.get('passed') is True and all(record.get(name) is None for name in errors)


def bounded(path, base):
    base = Path(base)
    require(base.is_relative_to(ROOT), 'Evidence base escaped repository')
    path = Path(path)
    if not path.is_absolute():
        path = base / path
    require(path.is_relative_to(base), 'Evidence path escaped its repository boundary')
    for part in path.relative_to(base).parts:
        require(part not in ('', '.', '..'), 'Noncanonical evidence path')
    cursor = ROOT
    for part in path.relative_to(ROOT).parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), f'Evidence symlink refused: {cursor}')
    require(path.resolve().is_relative_to(base.resolve()), 'Resolved evidence escaped boundary')
    return path


def read_json(path):
    require(path.is_file() and path.stat().st_size <= 16 * 1024 * 1024,
            f'Missing/oversized JSON: {path}')
    value = json.loads(path.read_text())
    require(isinstance(value, dict), 'Evidence JSON must be an object')
    return value


def link(base, record):
    require(isinstance(record, dict) and isinstance(record.get('path'), str), 'Missing evidence link')
    path = bounded(record['path'], base)
    require(path.is_file(), f'Missing linked evidence: {path}')
    require(sha_file(path) == record.get('sha256'), f'Evidence digest mismatch: {path}')
    return path


def snapshot(base, record):
    require(record.get('bytes') == DISK_BYTES, 'Wrong declared raw snapshot extent')
    require(bounded(record['path'], base).stat().st_size == DISK_BYTES, 'Wrong raw snapshot file extent')
    path = link(base, record)
    data = path.read_bytes()
    require(len(data) == DISK_BYTES and record.get('bytes') == DISK_BYTES, 'Wrong raw snapshot extent')
    require(sha(data[:SECTOR]) == record.get('seed_sha256'), 'Seed digest differs')
    require(sha(data[SECTOR:2 * SECTOR]) == record.get('record_sha256'), 'Legacy LBA1 digest differs')
    return data


def code_path(path):
    pure = Path(path)
    require(pure.parts and not pure.is_absolute() and '..' not in pure.parts, 'Invalid source-input path')
    if pure.parts[0] in ('docs', 'architecture', 'project', 'LICENSES') or pure.parts[:2] == ('tools', 'm3'):
        return False
    return pure.suffix.lower() not in ('.md', '.txt', '.rst') and pure.name not in ('LICENSE', 'NOTICE')


def code_sources():
    result = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
                            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    sources = {}
    for name in sorted(set(result.stdout.decode().split('\0')) - {''}):
        if code_path(name):
            path = bounded(name, ROOT)
            if path.is_file():
                sources[name] = sha(path.read_bytes())
    require(sources, 'No code source inputs found')
    return sources


def source_match(manifest, current):
    rows = manifest.get('source_inputs')
    require(isinstance(rows, list), 'Retained manifest lacks complete source inputs')
    recorded = {}
    all_paths = set()
    for row in rows:
        require(isinstance(row, dict), 'Source input must be an object')
        name = row.get('path')
        require(isinstance(name, str) and name not in all_paths, 'Duplicate/malformed source input')
        all_paths.add(name)
        require(re.fullmatch('[0-9a-f]{64}', row.get('sha256', '')), 'Invalid source digest')
        if code_path(name):
            recorded[name] = row['sha256']
    missing = sorted(current.keys() - recorded.keys())
    extra = sorted(recorded.keys() - current.keys())
    changed = sorted(name for name in current.keys() & recorded.keys()
                     if current[name] != recorded[name])
    require(not (missing or extra or changed),
            f'Retained CODE source mismatch: missing={missing[:5]} removed={extra[:5]} changed={changed[:5]}')


def verify_manifest(path, fixture, current):
    manifest = read_json(path)
    require(manifest.get('schema') == 1 and manifest.get('fixture') == fixture
            and manifest.get('qemu_test_exit') is True, 'Wrong retained build fixture/schema')
    require(re.fullmatch('[0-9a-f]{64}', manifest.get('build_id', '')), 'Invalid build identity')
    source_match(manifest, current)
    output = ROOT / 'build/m0'
    for row in [manifest['kernel'], manifest['image'], manifest['loader'], manifest['image_builder'],
                *manifest.get('supervisor', [])]:
        link(output, row)
    return manifest


def read_record(data, kind):
    require(len(data) == SECTOR and data[:8] == b'EVSTORE1', 'Invalid v2 durable record magic')
    require(int.from_bytes(data[8:10], 'little') == 2 and data[10] == kind,
            'Current-format v2 record required; v1 is not reused as v2 proof')
    require(not any(data[11:16]) and not any(data[34:64]), 'Durable reserved header bytes changed')
    length = int.from_bytes(data[32:34], 'little')
    require(length <= 416 and not any(data[64 + length:480]), 'Noncanonical durable payload')
    require(hashlib.sha256(data[:480]).digest() == data[480:], 'Durable record checksum mismatch')
    return int.from_bytes(data[16:24], 'little'), int.from_bytes(data[24:32], 'little'), data[64:64 + length]


def wide(data, offset):
    return int.from_bytes(data[offset:offset + 8], 'little')


def store_state(data):
    roots = []
    for sector in (16, 17):
        try:
            seq, op, body = read_record(data[sector * SECTOR:(sector + 1) * SECTOR], 1)
            require(len(body) == 384 and seq == op + 1, 'Invalid v2 root body/high-water')
            roots.append((seq, op, body))
        except ValueError:
            pass
    require(roots, 'No current-format committed v2 root')
    roots.sort(key=lambda row: row[0])
    if len(roots) == 2 and roots[0][0] == roots[1][0]:
        require(roots[0] == roots[1], 'Conflicting equal-sequence roots')
    seq, op, body = roots[-1]
    require(body[0] < 2 and body[1] <= 2 and body[6] < 2, 'Root slot bounds')
    refs = []
    for index in range(2):
        row = body[16 + index * 80:96 + index * 80]
        refs.append((wide(row, 0), row[8:40], row[40:72], int.from_bytes(row[72:74], 'little')))
    selected = refs[body[0]]
    sector = 26 + body[0]
    generation, related, content = read_record(data[sector * SECTOR:(sector + 1) * SECTOR], 2)
    require(generation == selected[0] and related == 0 and len(content) == selected[3]
            and hashlib.sha256(content).digest() == selected[1], 'Selected generation reference differs')
    sector = 28 + body[6]
    revision, related, payload = read_record(data[sector * SECTOR:(sector + 1) * SECTOR], 3)
    require(revision == wide(body, 184) and related == 1
            and len(payload) == int.from_bytes(body[176:178], 'little')
            and hashlib.sha256(payload).digest() == body[192:224], 'Mutable reference differs')
    return dict(sequence=seq, operation=op, selected=selected[0],
                known_good=None if body[1] == 2 else refs[body[1]][0], phase=body[3],
                boot_serial=wide(body, 256), highest=wide(body, 8), payload=payload,
                manifest=content, failure=body[272:384])


def guards(before, after):
    require(len(before) == len(after) == DISK_BYTES, 'Wrong guard comparison extent')
    require(before[:16 * SECTOR] == after[:16 * SECTOR]
            and before[30 * SECTOR:] == after[30 * SECTOR:], 'Guest changed a protected/control sector')


def control_change(before, after):
    require(before[:2 * SECTOR] == after[:2 * SECTOR]
            and before[3 * SECTOR:] == after[3 * SECTOR:], 'Host changed more than control LBA2')


def boot_record(directory, fixture, current, cut=None):
    result = read_json(directory / 'results.json')
    require(result.get('passed') is True and result.get('error') is None and result.get('requested_runs') == 1
            and result.get('cpus') == 1 and len(result.get('runs', [])) == 1, 'Boot did not pass one fresh VM')
    manifest = verify_manifest(directory / 'manifest.json', fixture, current)
    require(result.get('build_id') == manifest['build_id'], 'Boot/build identities differ')
    run = result['runs'][0]
    require(run.get('passed') is True and run.get('error') is None and run.get('directory') == 'run-001', 'Wrong boot run')
    serial_path = directory / 'run-001/serial.log'
    serial_bytes = serial_path.read_bytes()
    require(len(serial_bytes) <= 1024 * 1024 and sha(serial_bytes) == run.get('serial_sha256'), 'Serial hash/extent differs')
    require(sha((directory / 'run-001/qemu.stderr.log').read_bytes()) == run.get('qemu_stderr_sha256'), 'QEMU stderr hash differs')
    serial = serial_bytes.decode()
    binding.parse(serial)
    if cut is None:
        require(run.get('exit_status') == 33 and not run.get('interruption_expected'), 'Normal boot did not exit through PASS')
        binding.verify(directory, 1)
    else:
        require(run.get('exit_signal') == 9 and run.get('interruption_expected') is True
                and run.get('expected_cut') == cut and result.get('kind') == 'store-cut', 'Cut was not an actual retained-child SIGKILL')
        lines = [line for line in serial.splitlines() if line]
        require(not any('EVROSION_M0_RESULT' in line or 'EVROSION_PANIC' in line or 'status=FAIL' in line for line in lines), 'Cut prefix contains final/failure records')
        prefix = rf'EVROSION_M3_STORE_CUT protocol=1 build={manifest["build_id"]} status=PASS scope=journal cut={cut} calls=([1-9][0-9]*) blocks=\1 wakes=\1 replies=\1 mutations={cut} fault_vector=6 fault_error=0 process=[1-9][0-9]* thread=[1-9][0-9]* frames=true metadata=true guards=true'
        require(re.fullmatch(prefix, lines[-1]), 'Cut prefix is missing, duplicated or malformed')
        require(sum(line.startswith('EVROSION_M3_STORE_CUT ') for line in lines) == 1, 'Duplicate cut marker')
    return manifest


def verify_pio(evidence, result, current):
    expected = bytearray(DISK_BYTES)
    expected[:SECTOR] = bytes((index * 17 + 0x53) % 256 for index in range(SECTOR))
    require(snapshot(evidence, result['result']['initial_disk']) == expected, 'PIO initial fixture differs')
    expected[SECTOR:2 * SECTOR] = bytes((index * 29 + 0xa7) % 256 for index in range(SECTOR))
    require(len(result.get('phase_summaries', [])) == 2, 'PIO needs two phase summaries')
    builds = []
    for phase, row in zip(('write', 'verify'), result['phase_summaries']):
        path = link(evidence, row)
        require(path == evidence / phase / 'phase-result.json', 'PIO phase link/order differs')
        record = read_json(path)
        require(passed(record) and record.get('phase') == phase, 'PIO phase did not pass')
        require(snapshot(evidence, record['disk']) == expected, 'PIO exact committed/guard bytes differ')
        retained = verify_manifest(evidence / phase / 'manifest.json', 'm3-pio-' + phase, current)
        actual = boot_record(evidence / phase / 'boot', 'm3-pio-' + phase, current)
        require(retained == actual, 'PIO retained and boot manifests differ')
        builds.append(actual['build_id'])
    require(builds[0] != builds[1], 'PIO write/verify must have distinct retained builds')
    require(snapshot(evidence, result['final_disk']) == expected, 'PIO final bytes differ')
    return dict(boots=2, current_code=True, exact_disk=True)


def journal_case_snapshots(evidence, result):
    names = ['initial', *(f'cut-{cut}' for cut in range(1, 7)), 'normal-commit']
    require(len(result.get('cases', [])) == len(names), 'Journal case count differs')
    final = {}
    for name, row in zip(names, result['cases']):
        path = link(evidence, row)
        require(path == evidence / name / 'case-result.json', 'Journal case link/order differs')
        record = read_json(path)
        require(passed(record) and record.get('case') == name, 'Journal case did not pass')
        final[name] = snapshot(path.parent, record['final_disk'])
    return final


def verify_journal(evidence, result, current):
    require(result.get('expected_boots') == result.get('boot_invocations') == 15, 'Journal needs fifteen actual boot invocations')
    retained = verify_manifest(evidence / 'manifest.json', 'm3-store', current)
    require(link(evidence, result['build']['record']) == evidence / 'manifest.json', 'Journal retained build link differs')
    baseline = link(evidence, result['baseline']).read_bytes()
    require(len(baseline) == DISK_BYTES, 'Journal initial baseline extent differs')
    initial = store_state(baseline)
    require(initial['operation'] == 0 and initial['sequence'] == 1
            and initial['known_good'] is None and initial['payload'] == b'owner-data-A', 'Journal baseline fabricated health/operation')
    phases = [('initial/01-init', 0, 0)]
    for cut in range(1, 7):
        phases += [(f'cut-{cut}/01-cut', 1, cut), (f'cut-{cut}/02-recover', 2, 0)]
    phases += [('normal-commit/01-commit', 3, 0), ('normal-commit/02-verify', 4, 0)]
    require(len(result.get('phases', [])) == len(phases), 'Journal phase count differs')
    final = journal_case_snapshots(evidence, result)
    previous = {}
    for (name, mode, cut), row in zip(phases, result['phases']):
        path = link(evidence, row)
        require(path == evidence / name / 'phase-result.json', 'Journal phase order/path differs')
        record = read_json(path)
        require(passed(record) and record.get('mode') == mode
                and record.get('cut') == cut, 'Journal phase did not pass exact mode/cut')
        directory = path.parent
        before = snapshot(directory, record['before'])
        after = snapshot(directory, record['after'])
        guards(before, after)
        if mode in (1, 3):
            control_change(baseline, before)
        case = name.split('/')[0]
        if mode in (2, 4):
            control_change(previous[case], before)
        previous[case] = after
        actual = boot_record(directory / 'boot', 'm3-store', current, cut if mode == 1 else None)
        require(actual == retained, 'Journal did not reuse exactly one retained image')
        require(link(directory, record['boot']) == directory / 'boot/results.json', 'Journal boot link differs')
        if mode != 1:
            state = store_state(after)
            require(state['known_good'] is None and state['boot_serial'] == 0
                    and state['payload'] == (b'owner-data-A' if mode == 0 else b'owner-data-B')
                    and state['operation'] == (0 if mode == 0 else 1), 'Journal raw state differs')
            require(record['validation']['observer']['mutation_attempts'] == 0, 'Host repaired journal proof')
        if mode == 4:
            require(before == after, 'Journal Verify changed disk')
        if mode in (0, 2, 4):
            require(after == final[case], 'Journal final sealed snapshot differs from its final phase')
    return dict(boots=15, format=2, current_code=True, actual_kills=6, read_only_observer=True)


def budget_record(value):
    fields = ('elapsed_ticks', 'cpu_driver', 'cpu_client', 'cpu_critical',
              'cpu_parent', 'transitions', 'max_pending')
    require(isinstance(value, dict) and set(value) == set(fields)
            and all(type(value[name]) is int and 0 <= value[name] < 1 << 64 for name in fields),
            'Missing/malformed actual generation budget diagnostics')
    require(value['elapsed_ticks'] < 2048 and value['cpu_parent'] == value['elapsed_ticks']
            and sum(value[name] for name in ('cpu_driver', 'cpu_client', 'cpu_critical')) == value['cpu_parent']
            and all(value[name] <= 2048 for name in ('cpu_driver', 'cpu_client', 'cpu_critical'))
            and 1 <= value['transitions'] <= 100_000 and value['max_pending'] == 1,
            'Actual generation CPU accounting is unbalanced or exhausted')
    return value


def verify_generation(evidence, result, current, progress=False):
    fixture = 'm3-progress' if progress else 'm3-generation'
    prefix = 'm3-progress' if progress else 'm3-generation'
    failed_image = 'supervisor-generation-silent.elf' if progress else 'supervisor-generation-bad.elf'
    reason = 2 if progress else 1
    require(result.get('format') == 2 and result.get('boot_invocations') == result.get('expected_boots') == 5,
            'Generation needs five current-format boots')
    retained = verify_manifest(evidence / 'manifest.json', fixture, current)
    require(link(evidence, result['build']['record']) == evidence / 'manifest.json', 'Generation manifest link differs')
    catalogue = link(evidence, result['catalogue']).read_bytes()
    require(len(catalogue) == 512 and catalogue[:8] == b'EVGCAT01'
            and catalogue[8:12] == bytes((1, 0, 0, 2))
            and catalogue[12:16] == bytes((1, 0, 3, 0)) and not any(catalogue[240:]),
            'Generation catalogue differs')
    require(catalogue[16:48].hex() == retained['build_id'], 'Catalogue/kernel input identity differs')
    for offset, name in [(48, prefix + '-client.elf'), (80, 'm3-block-driver.elf'),
                         (112, 'supervisor-generation-good.elf'), (144, failed_image)]:
        rows = [row for row in retained['supervisor'] if Path(row['path']).name == name]
        require(len(rows) == 1 and catalogue[offset:offset + 32].hex() == rows[0]['sha256'], 'Catalogue actual component differs')
    require(read_json(link(evidence, result['catalogue_binding'])).get('passed') is True, 'Catalogue binding did not pass')
    phases = [('provision-a', 4, 1, 1, 23), ('fail-b', 10, 2, 2, 28),
              ('auto-a', 14, 3, 2, 18), ('manual-a', 21, 4, 3, 32), ('verify', 21, 4, 3, 0)]
    require(len(result.get('phases', [])) == 5, 'Generation phase count differs')
    previous = None
    capsule = None
    budgets = []
    for (name, op, serial, highest, mutations), row in zip(phases, result['phases']):
        path = link(evidence, row)
        require(path == evidence / name / 'phase-result.json', 'Generation phase order/path differs')
        record = read_json(path)
        require(passed(record) and record.get('phase') == name, 'Generation phase failed')
        directory = path.parent
        before = snapshot(directory, record['before'])
        after = snapshot(directory, record['after'])
        guards(before, after)
        if previous is not None:
            control_change(previous, before)
        previous = after
        state = store_state(after)
        transcript = (b'evrosion.generation.cohort.v1\0' + (1).to_bytes(8, 'little')
                      + catalogue[16:144] + catalogue[176:240]
                      + (1).to_bytes(2, 'little') + (3).to_bytes(4, 'little'))
        selected = state['manifest']
        require(len(selected) == 192 and selected[:16] == b'EVGEN001\x01\x00\x01\x00\x03\x00\x00\x00'
                and wide(selected, 16) == 1 and selected[24:56] == hashlib.sha256(transcript).digest()
                and selected[56:88] == catalogue[112:144]
                and selected[88:120] == catalogue[176:208]
                and selected[120:152] == catalogue[208:240] and not any(selected[152:]),
                'Stored selected cohort does not match the complete retained catalogue')
        require(state['operation'] == op and state['sequence'] == op + 1
                and state['boot_serial'] == serial and state['highest'] == highest
                and state['known_good'] == state['selected'] == 1 and state['phase'] == 0
                and state['payload'] == (b'owner-data-A' if name == 'provision-a' else b'owner-data-B'),
                'Generation raw committed state differs')
        actual = record['validation']['actual']
        budgets.append(budget_record(record['validation']['budget']))
        require(actual['operation'] == op and actual['sequence'] == op + 1
                and actual['mutations'] == mutations and actual['mode'] == name,
                'Actual generation receipt/count differs')
        require(actual['failure_reason'] == (0 if name == 'provision-a' else reason),
                'Actual generation failure reason differs from selected experiment')
        if progress and name == 'fail-b':
            progress_record(record['validation'].get('progress'))
        require(record['validation']['raw']['mutation_attempts'] == 0, 'Host repaired generation proof')
        failure = state['failure']
        if name == 'provision-a':
            require(not any(failure), 'Initial A fabricated a failure')
        else:
            require(failure[0:4] == bytes((1, reason, 1, 1)) and wide(failure, 8) == 2
                    and wide(failure, 16) == 2 and wide(failure, 24) == 10 and wide(failure, 32) == 11
                    and failure[40:72] == catalogue[144:176] and any(failure[72:104])
                    and not any(failure[4:8]) and not any(failure[104:112]),
                    'Raw failure capsule lost B identity/actual admission')
            if capsule is None:
                require(failure[72:104].hex() == actual['process_stamp'], 'Failure stamp differs from actual B')
                capsule = failure
            require(failure == capsule, 'B failure was overwritten after journal reuse')
        actual_build = boot_record(directory / 'boot', fixture, current)
        generation_diagnostics((directory/'boot/run-001/serial.log').read_text(),actual,record['validation']['budget'],catalogue,state,progress,after)
        require(actual_build == retained, 'Generation did not reuse exactly one image')
        require(link(directory, record['boot']) == directory / 'boot/results.json', 'Generation boot link differs')
        if name == 'verify':
            require(before == after and actual['booted'] == actual['boot_serial'] == 0,
                    'Verify mutated state or fabricated another boot')
    require(snapshot(evidence, result['final_disk']) == previous, 'Generation final disk differs')
    return dict(boots=5, format=2, current_code=True, mutable_preserved=True,
                capsule_survives_receipt_reuse=True, read_only_observer=True,
                actual_budget_records=budgets, failure_reason=reason)


def progress_record(value):
    names = ('start_tick', 'observed_tick', 'stop_tick')
    require(isinstance(value, dict) and set(value) == set(names)
            and all(type(value[n]) is int and 0 <= value[n] < (1 << 64) for n in names),
            'Missing/noncanonical actual progress timing')
    require(value['start_tick'] + 64 < (1 << 64)
            and value['observed_tick'] >= value['start_tick'] + 64
            and value['stop_tick'] >= value['observed_tick'], 'Live progress window was reset/truncated')
    return value


"""Independent physical-evidence validators; no builds or VM execution on import."""

FILE_FIELDS = ('status scope phase calls blocks wakes replies outer backend nested startup '
               'pre_delivery delivered_nested max_pending mutations snapshots authority_denied '
               'block_denied unbound_denied bindings mapped frames metadata guards report').split()
OWNER_FIELDS = ('status scope phase decision calls blocks wakes replies mutations starts ready '
                'critical_ready faults stops reaps forged uart_inputs uart_outputs catalogue frames '
                'metadata guards report uart_rx_before_tx uart_rx').split()


def serial_fields(serial, tag, names):
    require(len(serial.encode()) <= 1024 * 1024, 'Oversized actual serial')
    lines = [line.rstrip('\r\n') for line in serial.splitlines(keepends=True)
             if line.startswith(tag + ' ')]
    require(len(lines) == 1, f'Missing/duplicate {tag}')
    parts = lines[0].split(' ')
    require(len(parts) == len(names) + 1 and parts[0] == tag, f'Wrong {tag} field count')
    result = {}
    for key, field in zip(names, parts[1:]):
        require(field.startswith(key + '='), f'Noncanonical {tag} field order')
        result[key] = field[len(key) + 1:]
    return result


def uint(text):
    require(isinstance(text, str) and re.fullmatch(r'0|[1-9][0-9]*', text), 'Noncanonical unsigned integer')
    value = int(text)
    require(value < 1 << 64, 'Unsigned integer overflow')
    return value


def hex_bytes(text, count):
    require(isinstance(text, str) and len(text) == count * 2
            and re.fullmatch('[0-9a-f]*', text), 'Wrong/noncanonical hexadecimal extent')
    return bytes.fromhex(text)


def file_report(serial):
    f = serial_fields(serial, 'EVROSION_M3_FILE', FILE_FIELDS)
    for key, value in dict(status='PASS', scope='object', max_pending='2', authority_denied='1',
                           block_denied='1', unbound_denied='1', bindings='2', mapped='4',
                           frames='true', metadata='true', guards='true').items():
        require(f[key] == value, 'File authority/lifetime fact differs')
    body = hex_bytes(f['report'], 256)
    require(body[:5] == b'EVFC\x01' and body[5] in (0, 1) and body[6:8] == b'\x01\0'
            and not any(body[136:]), 'File Completion format/reserved bytes differ')
    write = body[5] == 0
    numbers = [wide(body, offset) for offset in range(8, 104, 8)]
    expected = [1, 1, 11 if write else 7, 1, 2, 2, int(write), int(write), int(write), 1, 1, int(write)]
    require(numbers == expected and body[104:136] == hashlib.sha256(b'file-content-B').digest(),
            'File app did not observe exact phase/permission/counter outcomes')
    require(f['phase'] == ('write' if write else 'verify'), 'File phase differs')
    n = {key:uint(f[key]) for key in FILE_FIELDS if key in ('calls', 'blocks', 'wakes', 'replies',
         'outer', 'backend', 'nested', 'startup', 'pre_delivery', 'delivered_nested', 'mutations', 'snapshots')}
    require(0 < n['calls'] <= 100_000 and all(n[key] == n['calls'] for key in ('blocks', 'wakes', 'replies'))
            and n['calls'] == n['outer'] + n['backend'] and n['outer'] == numbers[2]
            and n['backend'] == n['startup'] + n['nested'] and n['startup'] > 0
            and n['nested'] == n['delivered_nested'] > 0 and n['pre_delivery'] == 0
            and n['mutations'] == (11 if write else 0) and n['snapshots'] == int(write),
            'File calls, protected delivery, snapshot or mutation totals differ')
    return f, n


def file_envelope(body):
    require(32 <= len(body) <= 256 and body[:8] == b'EVFILE01' and body[8:10] == b'\x01\0'
            and not any(body[12:16]), 'File internal envelope format differs')
    size = int.from_bytes(body[10:12], 'little')
    require(size <= 224 and len(body) == size + 32, 'File envelope exact length differs')
    counter, operation = wide(body, 16), wide(body, 24)
    require(counter < (1 << 64) - 1 and operation < (1 << 64) - 1
            and (counter == 0) == (operation == 0), 'File envelope receipt/counter differs')
    return counter, operation, body[32:]


def journal_operation(data, operation):
    lba = 18 + operation % 8
    found, base, body = read_record(data[lba * 512:(lba + 1) * 512], 4)
    require(found == operation and base == operation and len(body) == 312
            and not any(body[4:8]), 'Original operation receipt/base differs')
    size = int.from_bytes(body[2:4], 'little')
    require(size <= 256 and not any(body[56 + size:])
            and hashlib.sha256(body[:24] + body[56:]).digest() == body[24:56],
            'Original operation fingerprint/body differs')
    return body


def verify_file(evidence, result, current):
    require(result.get('format') == 2 and result.get('boot_invocations') == result.get('expected_boots') == 2,
            'File needs two current-format cold boots')
    retained = verify_manifest(evidence / 'manifest.json', 'm3-file', current)
    require(link(evidence, result['build']['record']) == evidence / 'manifest.json', 'File manifest link differs')
    components = result['components']
    require(components == read_json(evidence / 'component-binding.json') and passed(components),
            'File component binding differs')
    require([r['component'] for r in components['components']] ==
            ['m3-file-server.elf', 'm3-file-app.elf', 'm3-block-driver.elf'], 'File cohort order differs')
    for row in components['components']:
        actual = [a for a in retained['supervisor'] if Path(a['path']).name == row['component']]
        require(len(actual) == 1 and actual[0] == row['build_artifact']
                and sha_file(link(evidence, row['retained'])) == actual[0]['sha256'], 'File actual image differs')
    require(len(result.get('phases', [])) == 2, 'File phase count differs')
    previous = None
    for index, (name, row) in enumerate(zip(('write', 'verify'), result['phases'])):
        path = link(evidence, row)
        require(path == evidence / name / 'phase-result.json', 'File phase order differs')
        phase = read_json(path)
        require(passed(phase) and phase.get('phase') == name, 'File phase failed')
        before, after = snapshot(path.parent, phase['before']), snapshot(path.parent, phase['after'])
        guards(before, after)
        if previous is not None:
            control_change(previous, before)
        previous = after
        state = store_state(after)
        require(state['operation'] == 1 and state['sequence'] == 2 and state['selected'] == 1
                and state['known_good'] is None and state['phase'] == 2 and state['boot_serial'] == 0
                and state['highest'] == 1 and not any(state['failure'])
                and file_envelope(state['payload']) == (1, 1, b'file-content-B'), 'File raw state/receipt differs')
        receipt = journal_operation(after, 1)
        require(receipt[0:2] == b'\x06\0' and wide(receipt, 8) == wide(receipt, 16) == 0
                and receipt[56:56 + len(state['payload'])] == state['payload'], 'File exact original receipt differs')
        require(boot_record(path.parent / 'boot', 'm3-file', current) == retained, 'File did not reuse exact image')
        serial = (path.parent / 'boot/run-001/serial.log').read_text()
        f, counts = file_report(serial)
        require(f['phase'] == name, 'File actual phase differs')
        actual = phase['validation']['actual']
        require(actual['completion_hex'] == f['report'] and all(actual[n] == value for n, value in counts.items()),
                'File retained validation differs from actual serial')
        b = serial_fields(serial, 'EVROSION_M3_FILE_BUDGET',
             'status elapsed_ticks limit_ticks driver_cpu server_cpu app_cpu parent_cpu transitions max_pending accounted bounded'.split())
        require(b['status'] == 'PASS' and b['limit_ticks'] == '2048' and b['accounted'] == b['bounded'] == 'true', 'File budget flags differ')
        budget = {name:uint(b[key]) for name,key in [('elapsed_ticks','elapsed_ticks'),('cpu_driver','driver_cpu'),
            ('cpu_server','server_cpu'),('cpu_app','app_cpu'),('cpu_parent','parent_cpu'),('transitions','transitions'),('max_pending','max_pending')]}
        require(0 < budget['elapsed_ticks'] < 2048 and budget['cpu_parent'] == budget['elapsed_ticks']
                and sum(budget[n] for n in ('cpu_driver','cpu_server','cpu_app')) == budget['cpu_parent']
                and 1 <= budget['transitions'] <= 100000 and budget['max_pending'] == 2
                and budget == phase['validation']['budget'], 'File budget actual/retained accounting differs')
        require(phase['validation']['snapshot']['raw']['mutation_attempts'] == 0, 'File host repaired proof')
        if index:
            require(before == after, 'File cold Verify changed bytes')
    require(snapshot(evidence, result['final_disk']) == previous, 'File final disk differs')
    return dict(boots=2, current_code=True, private_snapshot=True, read_only_observer=True, scoped_object=1)


def catalogue_for(evidence, retained, prefix):
    catalogue = bounded('catalogue.bin', evidence).read_bytes()
    require(len(catalogue) == 512 and catalogue[:16] == b'EVGCAT01\x01\0\0\x02\x01\0\x03\0'
            and not any(catalogue[240:]) and catalogue[16:48].hex() == retained['build_id'],
            'Actual catalogue format/build differs')
    names = [(prefix + '-catalogue.bin', None), (prefix + '-client.elf', 48), ('m3-block-driver.elf', 80),
             ('supervisor-generation-good.elf', 112), ('supervisor-generation-bad.elf', 144)]
    for name, offset in names:
        rows = [a for a in retained['supervisor'] if Path(a['path']).name == name]
        require(len(rows) == 1, 'Missing/ambiguous actual catalogue component')
        expected = sha(catalogue) if offset is None else catalogue[offset:offset + 32].hex()
        require(rows[0]['sha256'] == expected, 'Actual catalogue role image differs')
    binding = read_json(bounded('catalogue-binding.json', evidence))
    require(passed(binding) and binding['catalogue_sha256'] == sha(catalogue), 'Catalogue binding did not pass')
    return catalogue


def selected_cohort(state, catalogue, generation, slot):
    image = catalogue[112:144] if slot == 'A' else catalogue[144:176]
    transcript = (b'evrosion.generation.cohort.v1\0' + generation.to_bytes(8, 'little')
                  + catalogue[16:112] + image + catalogue[176:240]
                  + b'\x01\0' + (3).to_bytes(4, 'little'))
    content = state['manifest']
    require(len(content) == 192 and content[:16] == b'EVGEN001\x01\0\x01\0\x03\0\0\0'
            and wide(content, 16) == generation and content[24:56] == hashlib.sha256(transcript).digest()
            and content[56:88] == image and content[88:152] == catalogue[176:240]
            and not any(content[152:]), 'Stored complete selected cohort differs')


def failure_capsule(body, catalogue, previous=None, reason=1):
    require(len(body) == 112 and body[:4] == bytes((1, reason, 1, 1)) and not any(body[4:8])
            and wide(body, 8) == wide(body, 16) == 2 and wide(body, 24) == 10 and wide(body, 32) == 11
            and body[40:72] == catalogue[144:176] and any(body[72:104]) and not any(body[104:]),
            'Raw failure capsule lost exact B identity/admission/receipt')
    require(previous is None or previous == body, 'Original B capsule was overwritten')
    return body


def generation_body(encoded):
    b = hex_bytes(encoded, 256)
    require(b[:5] == b'EVGR\x01' and b[5] <= 6 and b[7] <= 5, 'Bad generation completion header')
    names = ('booted selected known_good boot_serial process thread failure_generation failure_serial '
             'failure_reason negatives mutations operation sequence failure_operation failure_sequence').split()
    result = {name:wide(b,8 + index * 8) for index,name in enumerate(names)}
    result.update(mode=b[5], decision=b[7], flags=b[6])
    for index,name in enumerate(('catalogue','process_stamp','storage_probe','booted_cohort')):
        result[name] = b[128+index*32:160+index*32].hex()
    inactive = result['mode'] in (4,5) or result['mode'] == 6 and result['decision'] != 1
    expected_flags = 5 if result['mode'] == 1 else 9 if inactive else 3
    require(result['flags'] == expected_flags and result['known_good'] == 1
            and result['selected'] == (3 if result['mode'] == 5 or result['mode'] == 6 and inactive else 1)
            and result['sequence'] == result['operation'] + 1, 'Generation completion state/flags differ')
    if inactive:
        require(all(result[n] == 0 for n in ('booted','boot_serial','process','thread','negatives'))
                and result['process_stamp'] == result['booted_cohort'] == '00'*32,
                'Unexecuted phase fabricated an admission/health process')
    else:
        require(result['booted'] == (2 if result['mode'] == 1 else 1) and result['negatives'] == 4
                and all(0 < result[n] < (1<<64)-1 for n in ('boot_serial','process','thread'))
                and result['process_stamp'] != '00'*32 and result['booted_cohort'] != '00'*32,
                'Executed phase lacks actual process/attempt diagnostics')
    failure = tuple(result[n] for n in ('failure_generation','failure_serial','failure_reason','failure_operation','failure_sequence'))
    require(failure == (0,0,0,0,0) if result['mode'] == 0 else
            failure in ((2,2,1,10,11),(2,2,2,10,11)), 'Completion failure identity differs')
    return result


def actual_report_binding(report, catalogue, state):
    require(report['catalogue'] == sha(catalogue) and report['storage_probe'] == sha(state['payload']),
            'Actual health report differs from measured catalogue/raw owner data')
    if report['process']:
        slot = 2 if report['mode'] == 1 else 1
        image = catalogue[144:176] if slot == 2 else catalogue[112:144]
        cohort = hashlib.sha256(b'evrosion.generation.cohort.v1\0'+slot.to_bytes(8,'little')
            +catalogue[16:112]+image+catalogue[176:240]+b'\x01\0'+(3).to_bytes(4,'little')).digest()
        stamp = hashlib.sha256(b'evrosion.actual.generation.admission.v1\0'+catalogue[16:48]
            +report['booted'].to_bytes(8,'little')+report['boot_serial'].to_bytes(8,'little')
            +report['process'].to_bytes(8,'little')+report['thread'].to_bytes(8,'little')+cohort+image).hexdigest()
        require(report['booted_cohort'] == cohort.hex() and report['process_stamp'] == stamp,
                'Actual process/attempt/cohort stamp differs')


def latest_health_receipt(data, report, catalogue):
    if report['process']:
        op = journal_operation(data,report['operation'])
        failed = report['mode'] == 1
        image = catalogue[144:176] if failed else catalogue[112:144]
        expected = (bytes.fromhex(report['process_stamp']) + bytes.fromhex(report['booted_cohort'])
                    + image + catalogue[176:240] + b'\x01\0' + bytes.fromhex(report['storage_probe'])
                    + (0 if failed else 3).to_bytes(4,'little'))
        require(op[0] == 5 and op[1] == (report['failure_reason'] + 1 if failed else 1)
                and int.from_bytes(op[2:4],'little') == 198 and wide(op,8) == report['booted']
                and wide(op,16) == report['boot_serial'] and op[56:254] == expected,
                'Original health receipt differs from actual outcome/admission/probe')
    elif report['mode'] == 5 or report['mode'] == 6 and report['decision'] != 1:
        op = journal_operation(data,16)
        require(op[:4] == b'\x02\0\0\0' and wide(op,8) == 3 and wide(op,16) == 0,
                'Unexecuted owner phase lost its original Activate3 receipt')


def generation_diagnostics(serial, actual, budget, catalogue, state, progress=False, data=None):
    names = ('status scope phase calls blocks wakes replies mutations starts ready critical_ready '
             'faults stops reaps forged catalogue frames metadata guards report').split()
    f = serial_fields(serial,'EVROSION_M3_GENERATION',names)
    require(all(f[key] == value for key,value in dict(status='PASS',scope='cohort',catalogue='true',
        frames='true',metadata='true',guards='true').items()),'Generation actual proof flags differ')
    report = generation_body(f['report'])
    actual_report_binding(report,catalogue,state)
    if data is not None: latest_health_receipt(data,report,catalogue)
    phases = ['provision-a','fail-b','auto-a','manual-a','verify']
    require(report['mode'] < 5 and f['phase'] == actual['mode'] == phases[report['mode']], 'Generation actual phase differs')
    for name in report.keys() - {'mode','decision','flags'}:
        require(actual[name] == report[name], 'Generation retained report differs from actual serial')
    require(report['failure_reason'] == (0 if report['mode'] == 0 else 2 if progress else 1),
            'Actual generation source variant differs')
    active,failed = int(report['mode'] != 4),int(report['mode'] == 1)
    require(all(uint(f[n]) == active for n in ('starts','stops','reaps'))
            and uint(f['faults']) == int(failed and not progress) and uint(f['critical_ready']) == active-failed
            and uint(f['forged']) == report['negatives'],'Actual generation lifecycle differs')
    calls = uint(f['calls'])
    require(0 < calls <= 100000 and all(uint(f[n]) == calls for n in ('blocks','wakes','replies'))
            and uint(f['mutations']) == report['mutations'],'Generation actual waits/receipts differ')
    b = serial_fields(serial,'EVROSION_M3_GENERATION_BUDGET',
        'status elapsed_ticks limit_ticks driver_cpu controller_cpu critical_cpu parent_cpu transitions max_pending accounted bounded'.split())
    require(b['status'] == 'PASS' and b['limit_ticks'] == '2048' and b['accounted'] == b['bounded'] == 'true',
            'Generation actual budget flags differ')
    mapping = dict(elapsed_ticks='elapsed_ticks',cpu_driver='driver_cpu',cpu_client='controller_cpu',
        cpu_critical='critical_cpu',cpu_parent='parent_cpu',transitions='transitions',max_pending='max_pending')
    require({key:uint(b[value]) for key,value in mapping.items()} == budget,'Generation actual budget differs from retained JSON')
    timing = [line for line in serial.splitlines() if line.startswith('EVROSION_M3_PROGRESS ')]
    if progress and failed:
        p = serial_fields(serial,'EVROSION_M3_PROGRESS','status start_tick observed_tick stop_tick wait_ticks stopped_live fault'.split())
        require(p['status'] == 'PASS' and p['wait_ticks'] == '64' and p['stopped_live'] == 'true' and p['fault'] == 'false',
                'MissingProgress lacks actual live-stop facts')
        progress_record({n:uint(p[n]) for n in ('start_tick','observed_tick','stop_tick')})
    else: require(not timing,'Unexpected progress proof on another source/phase')


def owner_report(serial):
    f = serial_fields(serial, 'EVROSION_M3_OWNER', OWNER_FIELDS)
    require(all(f[n] == v for n,v in dict(status='PASS',scope='recovery',catalogue='true',
            frames='true',metadata='true',guards='true').items()), 'Owner proof flags differ')
    r = generation_body(f['report'])
    names = ['provision-a','fail-b','auto-a','manual-a','verify','owner-prepare3','owner-recover']
    decisions = ['none','continue','cancel','timeout','input-fault','input-budget']
    require(f['phase'] == names[r['mode']] and f['decision'] == decisions[r['decision']]
            and r['mode'] != 3 and (r['mode'] == 6 or r['decision'] == 0), 'Owner phase/decision differs')
    calls = uint(f['calls'])
    require(0 < calls <= 100000 and all(uint(f[n]) == calls for n in ('blocks','wakes','replies'))
            and uint(f['mutations']) == r['mutations'], 'Owner calls/mutations differ')
    active, failed = int(r['process'] != 0), int(r['mode'] == 1)
    require(all(uint(f[n]) == active for n in ('starts','stops','reaps')) and uint(f['critical_ready']) == active - failed
            and uint(f['faults']) == failed and uint(f['forged']) == r['negatives']
            and uint(f['ready']) <= active and (not active or failed or uint(f['ready']) == 1),
            'Owner actual lifecycle facts differ')
    require(r['known_good'] == 1 and r['sequence'] == r['operation'] + 1, 'Owner receipt/KnownGood differs')
    rx = hex_bytes(f['uart_rx'], len(f['uart_rx']) // 2)
    before = uint(f['uart_rx_before_tx'])
    require(len(rx) <= 128 and before <= len(rx) and len(rx) <= uint(f['uart_inputs']) <= 8_000_000
            and uint(f['uart_outputs']) <= 8_000_000, 'Owner UART counts exceed bounds')
    return r, rx[before:]


def chosen_line(bytes_):
    for line in re.finditer(rb'([^\r\n]*)[\r\n]', bytes_):
        choice = line.group(1).lstrip(b' \t')
        if choice in (b'r',b'R'): return 1
        if choice in (b'q',b'Q'): return 2
    return None


def owner_boot(evidence, retained, current, eof=False):
    if not eof:
        require(boot_record(evidence, 'm3-owner', current) == retained, 'Owner changed retained image')
    result = read_json(evidence / 'results.json')
    require(passed(result) and result.get('requested_runs') == 1 and result.get('cpus') == 1
            and len(result.get('runs',[])) == 1, 'Owner did not finish its actual boot/hostEOF proof')
    require(verify_manifest(evidence / 'manifest.json','m3-owner',current) == retained, 'Owner boot manifest differs')
    run = result['runs'][0]
    serial_bytes = bounded('run-001/serial.log',evidence).read_bytes()
    require(len(serial_bytes) <= 1024*1024 and sha(serial_bytes) == run['serial_sha256']
            and sha_file(evidence / 'run-001/qemu.stderr.log') == run['qemu_stderr_sha256'], 'Owner actual logs differ')
    serial = serial_bytes.decode()
    if eof:
        require(run.get('passed') is True and run.get('error') is None and run.get('exit_signal') == 9
                and run.get('owner_eof_no_action') is True and run.get('interruption_expected') is True
                and 'EVROSION_M3_OWNER status=' not in serial and 'EVROSION_M0_RESULT' not in serial
                and 'EVROSION_PANIC' not in serial, 'EOF was relabelled completed guest PASS/failure')
        binding.parse(serial)
    return serial


def owner_prompt(serial, retained, catalogue):
    f = serial_fields(serial,'EVROSION_M3_OWNER_PROMPT',
        'protocol build catalogue operation selected known_good failure_generation failure_serial deadline actions'.split())
    require(all(f[key] == value for key,value in dict(protocol='1',build=retained['build_id'],
        catalogue=sha(catalogue),operation='16',selected='3',known_good='1',failure_generation='2',
        failure_serial='2',actions='r,q').items()) and 0 < uint(f['deadline']) < (1 << 64)-1,
        'Owner prompt does not bind actual build/catalogue/prepared selection')
    require(f"Failed image: {catalogue[144:176].hex()}" in serial.splitlines(), 'Owner named wrong failed image')
    return f


def owner_budget(value):
    fields = ('elapsed','driver','controller','critical','parent','transitions')
    require(isinstance(value,dict) and set(value) == set(fields)
            and all(type(value[n]) is int and 0 <= value[n] < (1<<64) for n in fields)
            and value['elapsed'] < 65536 and value['elapsed'] == value['parent']
            and value['driver'] + value['controller'] + value['critical'] == value['parent']
            and 1 <= value['transitions'] <= 8_000_000, 'Owner actual CPU budget differs')


def owner_serial_budget(serial, value):
    owner_budget(value)
    f = serial_fields(serial,'EVROSION_M3_OWNER_BUDGET',
        'status elapsed_ticks limit_ticks driver_cpu controller_cpu critical_cpu parent_cpu parent_limit transitions transition_limit max_pending accounted bounded'.split())
    require(all(f[key] == expected for key,expected in dict(status='PASS',limit_ticks='65536',parent_limit='131072',
        transition_limit='8000000',max_pending='1',accounted='true',bounded='true').items()), 'Owner actual budget flags differ')
    mapping = dict(elapsed='elapsed_ticks',driver='driver_cpu',controller='controller_cpu',critical='critical_cpu',parent='parent_cpu',transitions='transitions')
    require({key:uint(f[field]) for key,field in mapping.items()} == value,'Owner retained budget differs from actual serial')


def no_guest_completion(value, before, after, prepared):
    require(prepared is not None and value.get('guest_completed') is False
            and value.get('guest_report') is None and 'actual' not in value
            and value.get('eof_no_action') is True and before == after,
            'EOF lacks earlier prepared state or fabricates a guest completion')
    control_change(prepared,before)


def prepared_phase_order(rows):
    indexes=[]
    for name in ('fail-b','owner-prepare3'):
        found=[(i,r) for i,r in enumerate(rows) if r.get('path') == name+'/phase-result.json']
        require(len(found) == 1,'Resume requires one exact FailB and one exact Prepare3 receipt')
        indexes.append(found[0])
    require(indexes[0][0] < indexes[1][0],'Resume preparation predates its actual B failure')
    return indexes


def verify_owner(evidence, result, current):
    retained = verify_manifest(evidence / 'manifest.json','m3-owner',current)
    require(link(evidence,result['build']['record']) == evidence / 'manifest.json', 'Owner manifest link differs')
    cat = catalogue_for(evidence,retained,'m3-owner')
    specs = [('provision-a',4,1,1,23,0),('fail-b',10,2,2,28,0),('auto-a',14,3,2,18,0),
             ('owner-prepare3',16,3,3,10,0),('cancel',16,3,3,0,2),('timeout',16,3,3,0,3),
             ('invalid-cancel',16,3,3,0,2),('eof',16,3,3,0,None),('continue',21,4,3,22,1),('verify',21,4,3,0,0)]
    require(result['suite']['boot_invocations'] == 10 and len(result['suite']['phases']) == 10,
            'Owner needs exactly ten actual VM invocations')
    previous = capsule = prepared = None
    for (name,op,serial,highest,mutations,decision),row in zip(specs,result['suite']['phases']):
        path = link(evidence,row)
        require(path == evidence / name / 'phase-result.json', 'Owner phase link/order differs')
        phase = read_json(path)
        require(passed(phase) and phase.get('phase') == name, 'Owner phase failed')
        before,after = snapshot(path.parent,phase['before']),snapshot(path.parent,phase['after'])
        guards(before,after)
        if previous is not None: control_change(previous,before)
        previous = after
        state = store_state(after)
        pending = 3 <= specs.index((name,op,serial,highest,mutations,decision)) <= 7
        selected_cohort(state,cat,3 if pending else 1,'B' if pending else 'A')
        require((state['operation'],state['sequence'],state['selected'],state['known_good'],state['phase'],
                 state['boot_serial'],state['highest']) == (op,op+1,3 if pending else 1,1,2 if pending else 0,serial,highest)
                and state['payload'] == (b'owner-data-A' if name == 'provision-a' else b'owner-data-B'),
                'Owner raw selected generation/data/counters differ')
        if name == 'provision-a': require(not any(state['failure']), 'Initial owner A invented failure')
        else: capsule = failure_capsule(state['failure'],cat,capsule)
        text = owner_boot(path.parent / 'boot',retained,current,eof=name=='eof')
        v = phase['validation']
        require(v['raw']['mutation_attempts'] == 0, 'Owner host repaired raw state')
        if name == 'eof':
            owner_prompt(text,retained,cat)
            no_guest_completion(v,before,after,prepared)
            continue
        r, fresh = owner_report(text)
        actual_report_binding(r,cat,state)
        latest_health_receipt(after,r,cat)
        require(v['guest_completed'] is True and r['operation'] == op and r['mutations'] == mutations
                and r['decision'] == decision and r['catalogue'] == sha(cat), 'Owner actual report differs')
        owner_serial_budget(text,v['budget'])
        if name == 'owner-prepare3': prepared = after
        if name in ('cancel','timeout','invalid-cancel','continue'):
            owner_prompt(text,retained,cat)
            inp = read_json(path.parent / 'boot/run-001/owner-input.json')
            written = bytes(row[1] for row in inp['written'])
            require(inp['eof_no_action'] is False and written == fresh and chosen_line(fresh) == (decision if decision in (1,2) else None),
                    'Owner decision does not match real submitted/received complete input')
        if mutations == 0: require(before == after, 'No-action/Verify changed raw disk')
    require(snapshot(evidence,result['final_disk']) == previous, 'Owner final disk differs')
    return dict(boots=10,current_code=True,guest_completed=9,host_eof_kills=1,real_prepared_baseline=True,
                mutable_preserved=True,read_only_observer=True)


def prepared_origin(origin, current):
    require(origin.get('schema') == 1 and origin.get('kind') == 'prepared-owner-import'
            and origin.get('read_only') is True and origin.get('publisher_authenticated') is False,
            'Resume origin is not a read-only measured receipt')
    source = bounded(origin['source'], ROOT)
    require(source.is_relative_to(ROOT / 'build/m3/evidence'), 'Resume source outside owned evidence')
    suite = read_json(link(source,origin['results']))
    require(suite.get('kind') == 'owner-recovery' and type(suite.get('passed')) is bool
            and suite['passed'] == origin['source_suite_passed'], 'Resume source-suite identity differs')
    # A later failed phase need not invalidate these earlier completed receipts.
    manifest = verify_manifest(link(source,origin['manifest']),'m3-owner',current)
    require(origin['manifest'] == suite['build']['record'] and origin['build_id'] == manifest['build_id'],
            'Resume retained source manifest differs')
    cat = catalogue_for(source,manifest,'m3-owner')
    require(origin['catalogue_sha256'] == sha(cat), 'Resume catalogue identity differs')
    rows = suite['suite']['phases']
    capsule = prepared = actual_prepared = None
    for name,(_,row) in zip(('fail-b','owner-prepare3'),prepared_phase_order(rows)):
        expected = origin['failed_phase' if name == 'fail-b' else 'prepared_phase']
        require(expected['record'] == row, 'Resume origin points at a different required phase')
        path = link(source,row)
        phase = read_json(path)
        require(passed(phase) and phase.get('phase') == name, 'Resume required earlier phase did not pass')
        require(expected['before'] == phase['before'] and expected['after'] == phase['after']
                and expected['boot'] == phase['boot'], 'Resume source receipt links differ')
        before,after = snapshot(path.parent,phase['before']),snapshot(path.parent,phase['after'])
        guards(before,after)
        text = owner_boot(path.parent/'boot',manifest,current)
        require(link(source,expected['serial']) == path.parent/'boot/run-001/serial.log', 'Resume actual source serial differs')
        r,_ = owner_report(text)
        require(phase['validation']['actual']['operation'] == r['operation']
                and phase['validation']['actual']['failure_reason'] == r['failure_reason']
                and r['decision'] == 0 and r['failure_reason'] == 1 and r['catalogue'] == sha(cat),
                'Resume source report differs from actual guest execution')
        state = store_state(after)
        actual_report_binding(r,cat,state)
        latest_health_receipt(after,r,cat)
        expected_op = 10 if name == 'fail-b' else 16
        require(state['operation'] == r['operation'] == expected_op and state['sequence'] == expected_op + 1
                and state['boot_serial'] == (2 if name == 'fail-b' else 3) and state['known_good'] == 1
                and state['selected'] == (1 if name == 'fail-b' else 3) and state['payload'] == b'owner-data-B',
                'Resume source raw generation/data differs')
        capsule = failure_capsule(state['failure'],cat,capsule)
        if name == 'fail-b':
            require(r['mode'] == 1 and r['process'] > 0 and r['thread'] > 0
                    and capsule[72:104].hex() == r['process_stamp'], 'Resume source lacks actual B fault admission')
        else:
            require(r['mode'] == 5 and r['process'] == r['thread'] == r['booted'] == r['boot_serial'] == 0
                    and r['selected'] == 3 and state['highest'] == 3 and state['phase'] == 2,
                    'Resume source lacks genuine unresolved Prepare3')
            selected_cohort(state,cat,3,'B')
            actual_prepared = phase['validation']['actual']
            require(origin['actual_prepared_report'] == actual_prepared, 'Resume manufactured its prepared baseline report')
            prepared = after
    return source, manifest, cat, prepared, capsule, actual_prepared


def verify_owner_resume(evidence, result, current):
    require(result.get('kind') == 'owner-resume' and result.get('boot_invocations') == 1
            and len(result.get('phases',[])) == 1 and result.get('source_snapshot_modified') is False,
            'Resume needs one fresh private-clone boot with source preservation')
    source,manifest,cat,prepared,capsule,baseline = prepared_origin(result['origin'],current)
    require(source != evidence and verify_manifest(link(evidence,result['build']['record']),'m3-owner',current) == manifest,
            'Resume changed measured image or reused source directory')
    require(catalogue_for(evidence,manifest,'m3-owner') == cat, 'Resume catalogue differs')
    path = link(evidence,result['phases'][0])
    require(path == evidence/'interactive/phase-result.json','Resume phase path differs')
    phase = read_json(path)
    require(passed(phase) and phase['phase'] == 'interactive','Resume phase did not pass')
    before,after = snapshot(path.parent,phase['before']),snapshot(path.parent,phase['after'])
    control_change(prepared,before)
    guards(before,after)
    # This is a NEW private data file, never the imported raw snapshot or source
    # VM's disk. Path/link/hash checks also reject aliasing via symlinks.
    disk = bounded('data.raw',evidence)
    require(disk.stat().st_size == DISK_BYTES and all(
        (disk.stat().st_dev,disk.stat().st_ino) != (p.stat().st_dev,p.stat().st_ino)
        for p in [source/'data.raw',source/'owner-prepare3/data-after.raw']), 'Resume reused a source disk inode')
    v = phase['validation']
    text = owner_boot(path.parent/'boot',manifest,current,eof=v.get('guest_completed') is False)
    owner_prompt(text,manifest,cat)
    require(v['raw']['mutation_attempts'] == 0,'Resume host repaired proof')
    state = store_state(after)
    failure_capsule(state['failure'],cat,capsule)
    require(state['payload'] == b'owner-data-B' and state['known_good'] == 1 and state['highest'] == 3,
            'Resume lost owner data/KnownGood/failure identity')
    if v['guest_completed']:
        r,fresh = owner_report(text)
        actual_report_binding(r,cat,state)
        latest_health_receipt(after,r,cat)
        require(r['mode'] == 6 and r['failure_reason'] == 1,'Resume used wrong actual owner profile')
        decision = r['decision']
        inp = read_json(path.parent/'boot/run-001/owner-input.json')
        require(inp['source'] == 'interactive-owner' and inp['eof_no_action'] is False
                and bytes(row[1] for row in inp['written']) == fresh and chosen_line(fresh) == decision,
                'Resume action lacks actual owner stdin/UART complete line')
        owner_serial_budget(text,v['budget'])
        if decision == 1:
            require((r['booted'],r['boot_serial'],r['mutations'],state['operation'],state['sequence'],
                     state['selected'],state['phase'],state['boot_serial']) == (1,4,22,21,22,1,0,4)
                    and r['process'] > 0 and r['thread'] > 0,'Resume did not actually boot KnownGoodA')
            selected_cohort(state,cat,1,'A')
        else:
            require(decision == 2 and before == after and (state['operation'],state['selected'],state['boot_serial']) == (16,3,3),
                    'Resume cancel changed prepared state')
    else:
        no_guest_completion(v,before,after,prepared)
        require((state['operation'],state['selected'],state['boot_serial']) == (16,3,3),'Resume EOF changed prepared state')
        decision = None
    require(snapshot(evidence,result['final_disk']) == after and disk.read_bytes() == after,'Resume final private disk differs')
    # Recheck the original links AFTER validation; the earlier receipts, source
    # manifest and raw snapshot must still have their import-time hashes.
    prepared_origin(result['origin'],current)
    return dict(boots=1,current_code=True,decision=decision,source_snapshot_modified=False,
                real_prepared_receipt=True,private_clone=True,read_only_observer=True)


def verify_workflow(kind, path, current):
    evidence = bounded(Path(path), ROOT)
    if evidence.name == 'results.json':
        evidence = evidence.parent
    require(evidence.is_relative_to(ROOT / 'build/m3/evidence'), 'Workflow evidence outside owned M3 directory')
    result = read_json(evidence / 'results.json')
    require(result.get('kind') == ('owner-resume' if kind == 'owner-resume' else NAMES[kind]) and passed(result), 'Workflow did not pass exact requested kind')
    proof = {'pio': verify_pio, 'journal': verify_journal, 'generation': verify_generation, 'file':verify_file, 'progress':lambda e,r,c:verify_generation(e,r,c,True), 'owner':verify_owner, 'owner-resume':verify_owner_resume}[kind](evidence, result, current)
    return dict(evidence=str((evidence / 'results.json').relative_to(ROOT)),
                sha256=sha((evidence / 'results.json').read_bytes()), subset_only=True, **proof)


def latest(kind):
    paths = [path for path in (ROOT / 'build/m3/evidence').glob(NAMES[kind] + '-*/results.json')
             if re.fullmatch(re.escape(NAMES[kind]) + r'-[0-9]+(?:-[0-9]+)?', path.parent.name)]
    require(paths, f'No retained {kind} evidence; run its owned workflow or use --fresh {kind}')
    # Never skip a newer failed experiment to make an older PASS look current.
    return max(paths, key=lambda path: path.stat().st_mtime_ns).parent


def fresh_evidence(kind, text):
    """Select one owned SUITE, ignoring its nested boot evidence announcements.

    Selection supplies no PASS: verify_workflow still checks exact result kind,
    linked bytes, manifests, source equivalence and physical/model scope below.
    """
    parent = ROOT / 'build/m3/evidence'
    pattern = re.escape(NAMES[kind]) + r'-[0-9]+-[0-9]+'
    found = set()
    for name in re.findall(r'^Evidence: ([^\r\n]+)\r?$', text, re.MULTILINE):
        path = Path(name)
        if not path.is_absolute():
            path = ROOT / path
        if path.parent == parent and re.fullmatch(pattern, path.name):
            found.add(bounded(path, parent))
    require(len(found) == 1, 'Fresh workflow did not identify exactly one owned top-level suite')
    return found.pop()


def extra_checks(options, initial):
    def checks(run, records):
        binding.extra_checks(run, records)
        run('m3-validator-tests', ['python3', '-m', 'unittest', 'discover', '-s', 'tools/m3', '-v'])
        run('store-block-host', ['cargo', 'test', '-p', 'ev-store', '-p', 'ev-block-service', '--all-features', '--locked', '--offline'])
        run('store-block-host-lint', ['cargo', 'clippy', '-p', 'ev-store', '-p', 'ev-block-service', '--lib', '--tests', '--all-features', '--locked', '--offline', '--', '-D', 'warnings'])
        run('store-target-lint', ['cargo', 'clippy', '-p', 'ev-store', '--lib', '--release', '--target', 'x86_64-unknown-none', '--locked', '--offline', '--', '-D', 'warnings'])
        for feature in ['test-write', 'test-verify', 'test-direct-fault', 'test-block-driver',
                        'test-block-client-write', 'test-block-client-verify', 'test-store-client', 'test-generation-client', 'test-owner-client']:
            run('block-' + feature + '-lint', ['cargo', 'clippy', '-p', 'ev-block-service', '--release', '--target', 'x86_64-unknown-none', '--features', feature, '--locked', '--offline', '--', '-D', 'warnings'])
        for feature in ['generation-good', 'generation-bad', 'generation-silent']:
            run('supervisor-' + feature + '-lint', ['cargo', 'clippy', '-p', 'ev-root-supervisor', '--release', '--target', 'x86_64-unknown-none', '--features', feature, '--locked', '--offline', '--', '-D', 'warnings'])
        run('generated-block-contract', ['python3', 'tools/idl/generate_block.py', '--check'])
        run('generated-file-contract', ['python3', 'tools/idl/generate_file.py', '--check'])
        run('file-core-host', ['cargo','test','-p','ev-file','-p','ev-file-service','--locked','--offline'])
        run('file-core-lint', ['cargo','clippy','-p','ev-file','-p','ev-file-service','--lib','--tests','--locked','--offline','--','-D','warnings'])
        run('file-core-target-lint', ['cargo','clippy','-p','ev-file','--lib','--release','--target','x86_64-unknown-none','--locked','--offline','--','-D','warnings'])
        for feature in ['server','app']:
            run('file-'+feature+'-target-lint',['cargo','clippy','-p','ev-file-service','--release','--target','x86_64-unknown-none','--features',feature,'--locked','--offline','--','-D','warnings'])
        for kind in NAMES:
            if kind in options.fresh:
                text = run('m3-' + kind + '-fresh', ['cargo', 'ev', 'test', {'pio':'storage-pio','journal':'storage-journal','generation':'storage-generation','file':'storage-file','progress':'storage-progress','owner':'storage-recovery'}[kind]])
                path = fresh_evidence(kind, text)
                record = records[-1]
                record['passed'] = False
            else:
                path = getattr(options, kind) or latest(kind)
                record = {'name': 'm3-' + kind + '-retained', 'command': ['validate-retained', str(path)], 'passed': False}
                records.append(record)
            try:
                require(code_sources() == initial, 'Active CODE changed during cumulative validation')
                record['proof'] = verify_workflow(kind, path, initial)
                record['passed'] = True
            except (ValueError, KeyError, OSError) as error:
                record['error'] = str(error)
                raise
        resumes = options.owner_resume
        if not resumes:
            resumes = sorted((ROOT/'build/m3/evidence').glob('owner-resume-*/results.json'),
                             key=lambda p:p.stat().st_mtime_ns)[-2:]
        require(len(resumes) >= 2 and len({str(p) for p in resumes}) == len(resumes),
                'Actual owner --from cancel and continue receipts are required')
        decisions = set()
        for index,path in enumerate(resumes):
            record = {'name':f'm3-owner-resume-{index+1}',
                      'command':['validate-retained-owner-resume',str(path)],'passed':False}
            records.append(record)
            try:
                require(code_sources() == initial,'Active CODE changed during resume validation')
                record['proof'] = verify_workflow('owner-resume',path,initial)
                decisions.add(record['proof']['decision'])
                record['passed'] = True
            except (ValueError,KeyError,OSError) as error:
                record['error'] = str(error)
                raise
        require({1,2} <= decisions,'Actual owner --from receipts do not prove both cancel and continue')
    return checks


def validator_sources():
    return {str(p.relative_to(ROOT)):sha_file(bounded(p,ROOT))
            for p in sorted((ROOT/'tools/m3').glob('*.py'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-resume',action='append',type=Path,default=[],help='Actual --from owner-resume evidence; repeat for cancel and continue receipts')
    for kind in NAMES:
        parser.add_argument('--' + kind, type=Path, help='Exact retained evidence directory or results.json within repository')
    parser.add_argument('--fresh', action='append', choices=list(NAMES), default=[],
                        help='Rerun only this owned workflow; repeat for multiple workflows')
    options = parser.parse_args()
    initial = code_sources()
    validators = validator_sources()
    temporary = ROOT / 'build/test-tmp'
    temporary.mkdir(parents=True, exist_ok=True)
    os.environ['TMPDIR'] = str(temporary)
    bootstrap.verify_boot = binding.verify
    parent = ROOT / 'build/m1/evidence'
    before = set(parent.glob('m3-subset-*'))
    sources = sorted(initial) + sorted(validators)
    status = bootstrap.main('M3-SUBSET-01', 'm3-subset',
        'Cumulative M1/M2 plus bounded PIO/journal/fault-and-progress generations/File/owner/actual-resume execution. '
        'NOT an automatic whole-M3 declaration: final readiness/A014 scope and tracker acceptance remain separate; cold boot-attempt exhaustion remains model-only. '
        'Guest VM restart/flush evidence is not host physical power-loss, production authentication or a consumer release.',
        sources, extra_checks=extra_checks(options, initial))
    created = set(parent.glob('m3-subset-*')) - before
    require(len(created) == 1, 'Cannot identify the newly owned cumulative evidence')
    path = created.pop() / 'results.json'
    result = read_json(path)
    unchanged = code_sources() == initial
    validators_unchanged = validator_sources() == validators
    result.update(subset_only=True, whole_m3_acceptance=False, code_source_scope=SOURCE_SCOPE,
                  retained_code_sha256=initial, code_unchanged_through_completion=unchanged,
                  validator_sha256=validators, validators_unchanged_through_completion=validators_unchanged)
    if not unchanged or not validators_unchanged:
        result['passed'] = False
        result['error'] = 'Active CODE or validator sources changed before cumulative completion'
        status = 1
    # Finalize ONLY this invocation's newly owned result, never retained input.
    path.write_text(json.dumps(result, indent=2) + '\n')
    path.chmod(0o444)
    return status


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f'FAIL M3 SUBSET: {error}', file=sys.stderr)
        sys.exit(1)
