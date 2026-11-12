#!/usr/bin/env python3
"""Independent ELF/manifest golden encoding; no compiler or silent regeneration."""
import hashlib
from pathlib import Path
import struct
from fixture import fixture as binding_manifest

ROOT = Path(__file__).resolve().parents[2]
BASE = 1 << 39
CODE = BASE + 4096
DATA = BASE + 3 * 4096


def image_fixture():
    code = bytearray()
    jumps = []

    def relative(opcode, address, suffix=b''):
        code.extend(opcode + struct.pack('<i', address - (CODE + len(code) + len(opcode) + 4 + len(suffix))) + suffix)

    def jne():
        jumps.append(len(code))
        code.extend(b'\x75\x00')

    relative(b'\x48\x83\x3d', DATA + 8, b'\x00')  # cmp qword [BSS],0
    jne()
    relative(b'\x48\x8b\x05', DATA)  # mov rax,[initialized data]
    relative(b'\x48\x89\x05', DATA + 8)  # mov [BSS],rax
    relative(b'\x48\x39\x05', DATA + 8)  # cmp [BSS],rax
    jne()
    code.extend(b'\x50\x59\x48\x39\xc1')  # push rax; pop rcx; cmp rcx,rax
    jne()
    success = len(code)
    code.extend(b'\x0f\x0b')  # exact successful terminal UD2
    fail = len(code)
    code.extend(b'\x0f\x0b')  # distinct IP forces a failing assertion
    for offset in jumps:
        code[offset + 1] = fail - offset - 2
    code.extend(b'\xcc' * (128 - len(code)))
    code.extend(b'\x48\x89\x37\x0f\x0b')  # +128: mov [rdi],rsi; ud2
    code.extend(b'\xcc' * (144 - len(code)))
    code.extend(b'\xff\xe7')  # +144: jmp rdi
    code.extend(b'\xcc' * (160 - len(code)))
    code.extend(b'\x48\x8b\x07\x0f\x0b')  # +160: mov rax,[rdi]; ud2
    code.extend(b'\xcc' * (256 - len(code)))
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    header = ident + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, CODE, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    headers = (struct.pack('<IIQQQQQQ', 1, 5, 4096, CODE, 0, len(code), 4096, 4096)
               + struct.pack('<IIQQQQQQ', 1, 6, 8192, DATA, 0, 8, 8192 + 17, 4096))
    image = bytearray(header + headers)
    image.extend(bytes(4096 - len(image)))
    image.extend(code)
    image.extend(bytes(8192 - len(image)))
    image.extend(struct.pack('<Q', 0x11223344556677C3))
    return bytes(image), success


def manifest_fixture():
    image, _ = image_fixture()
    manifest = bytearray(binding_manifest())
    manifest[16:48] = hashlib.sha256(image).digest()
    return bytes(manifest)


if __name__ == '__main__':
    image, success = image_fixture()
    for name, expected in [('bootstrap-static-v1.elf', image), ('bootstrap-static-v1.bin', manifest_fixture())]:
        if (ROOT / 'kernel/fixtures' / name).read_bytes() != expected:
            raise SystemExit('FAIL: independent executable fixture differs: ' + name)
    print('PASS: independent ELF image=' + hashlib.sha256(image).hexdigest()
          + ' manifest=' + hashlib.sha256(manifest_fixture()).hexdigest() + ' success_offset=' + str(success))
