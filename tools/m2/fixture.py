#!/usr/bin/env python3
"""Independently reproduce/check the Internal bootstrap binding golden vector."""
import hashlib
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    authority = hashlib.sha256(b'evrosion.bootstrap.authority.v1\0' + struct.pack('<Q', 2))
    for selector, kind, identity, lineage, rights in [(1, 1, 0, 0, 1), (2, 2, 1, 1, 8)]:
        authority.update(struct.pack('<QBQQHBQQ', selector, kind, identity, lineage, rights, 0, 0, 0))
    return (b'EVBM0001' + struct.pack('<Q', 100) + hashlib.sha256(b'abc').digest()
            + bytes([42]) * 32 + struct.pack('<QQQQB7xQ', 1000, 64, 4, 8, 3, 60)
            + authority.digest() + struct.pack('<B7x', 2)
            + struct.pack('<QBxH4xQQ', 1, 1, 1, 0, 0)
            + struct.pack('<QBxH4xQQ', 2, 2, 8, 0, 0))


if __name__ == '__main__':
    expected = fixture()
    actual = (ROOT / 'kernel/fixtures/bootstrap-whole-object-v1.bin').read_bytes()
    if actual != expected:
        raise SystemExit('FAIL: bootstrap golden vector differs from independent encoding')
    print('PASS: independent binding vector ' + hashlib.sha256(actual).hexdigest())
