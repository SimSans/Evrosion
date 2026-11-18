#!/usr/bin/env python3
"""Build/retain ONLY the additive workspace driver; no VM or admission claim.

Run through the task's run_command.py to retain the complete command/output.
Uses the established userspace large-code-model flags, not global kernel flags.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
target = Path(os.environ['CARGO_TARGET_DIR']).resolve()
assert target == root.parent / 'target', 'Use the task-owned shared target via run_command.py'
assert shutil.disk_usage(root).free >= 2 * 1024**3, 'Retain the initial2GiB disk reserve'
a.output.mkdir(parents=True, exist_ok=False)
lock_before = hashlib.sha256((root/'Cargo.lock').read_bytes()).hexdigest()
flags = ['-C', 'relocation-model=static', '-C', 'code-model=large',
         '-C', 'force-frame-pointers=yes', '-C', 'debuginfo=1',
         '-C', 'link-arg=--no-pie', '--cfg', 'curve25519_dalek_backend="serial"',
         '--remap-path-prefix=' + str(root) + '=/evrosion', '-Z', 'emit-stack-sizes']
env = os.environ.copy()
env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
command = ['cargo', 'build', '--offline', '--locked', '--release', '--target',
           'x86_64-unknown-none', '-p', 'ev-block-service', '--bin',
           'ev-block-service', '--features', 'workspace-driver']
(a.output/'BUILD_INPUTS.json').write_text(json.dumps({
    'argv': command, 'root': str(root), 'flags': flags,
    'Cargo.lock.sha256': lock_before, 'scope': 'One additive driver; no VM/admission result'
}, indent=2)+'\n')
subprocess.run(command, cwd=root, env=env, check=True)
artifact = target/'x86_64-unknown-none/release/ev-block-service'
raw = a.output/'workspace-block.unstripped.elf'
with raw.open('xb') as stream:
    stream.write(artifact.read_bytes())
def loaded_identity(data):
    assert data[:6] == b'\x7fELF\x02\x01'
    entry, phoff = struct.unpack_from('<QQ', data, 24)
    size, count = struct.unpack_from('<HH', data, 54)
    loads = []
    for index in range(count):
        kind, permissions, offset, virtual, _, filesz, memsz, align = struct.unpack_from(
            '<IIQQQQQQ', data, phoff+index*size)
        if kind == 1:
            loads.append((permissions,virtual,filesz,memsz,align,
                          hashlib.sha256(data[offset:offset+filesz]).hexdigest()))
    return entry, loads
sysroot = Path(subprocess.check_output(['rustc','--print','sysroot'],cwd=root,text=True).strip())
tools = list((sysroot/'lib/rustlib').glob('*/bin/llvm-objcopy'))
assert len(tools) == 1, 'Require one pinned llvm-tools-preview objcopy'
retained = a.output/'workspace-block.elf'
subprocess.run([str(tools[0]),'--strip-debug',str(raw),str(retained)],cwd=root,check=True)
data = retained.read_bytes()
assert loaded_identity(data) == loaded_identity(raw.read_bytes()), 'Debug separation changed loaded identity'
assert len(data) <= 1024*1024, 'Retain existing1MiB executable container bound'
assert data[:6] == b'\x7fELF\x02\x01'
entry, phoff = struct.unpack_from('<QQ', data, 24)
phentsize, phnum = struct.unpack_from('<HH', data, 54)
segments = []
for i in range(phnum):
    kind, permissions, offset, virtual, _, file_bytes, memory_bytes, align = struct.unpack_from(
        '<IIQQQQQQ', data, phoff+i*phentsize)
    if kind == 1:
        segments.append({'flags': permissions, 'virtual': virtual, 'file_bytes': file_bytes,
                         'memory_bytes': memory_bytes, 'pages': (memory_bytes+4095)//4096,
                         'align': align, 'offset': offset})
subprocess.run(['python3', str(root/'tools/m5/stack_audit.py'), '--userspace',
                str(retained), str(a.output/'STACK_AUDIT.json')], cwd=root, check=True)
lock_after = hashlib.sha256((root/'Cargo.lock').read_bytes()).hexdigest()
assert lock_before == lock_after, 'Locked package build must preserve global resolution'
report = {'scope': 'Actual linked single driver; no VM or frame-admission claim',
          'elf': str(retained), 'sha256': hashlib.sha256(data).hexdigest(),
          'unstripped_elf': str(raw), 'unstripped_sha256': hashlib.sha256(raw.read_bytes()).hexdigest(),
          'debug_separation_loaded_identity_equal': True,
          'bytes': len(data), 'entry': entry, 'segments': segments,
          'loaded_segment_pages': sum(s['pages'] for s in segments),
          'declared_cpu_frames_process_thread': [16384, 32, 1, 1],
          'Cargo.lock.sha256': lock_after,
          'free_bytes_after': shutil.disk_usage(root).free}
(a.output/'LINKED_PROFILE.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report))
