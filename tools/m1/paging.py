#!/usr/bin/env python3
"""M1-02a acceptance. Shares build/boot regression orchestration with M1-01."""
import re
import sys
import bootstrap


def verify_paging(evidence, expected_runs, bootstrap_record=True):
    records = original_verify(evidence, expected_runs, bootstrap_record)
    for index in range(1, expected_runs + 1):
        text = (evidence / f'run-{index:03}/serial.log').read_text()
        matches = re.findall(r'^EVROSION_M1_PAGING status=PASS roots=2 map_unmap=true '
            r'remap=true zeroed=true permissions=true restored=true root_a=(0x[0-9a-f]+) '
            r'root_b=(0x[0-9a-f]+) virtual=(0x[0-9a-f]+)\r?$', text, re.MULTILINE)
        if bootstrap_record:
            if len(matches) != 1:
                raise RuntimeError('Expected exactly one complete M1 paging proof per boot')
            a, b, address = (int(v, 16) for v in matches[0])
            if not (a != b and all(0 < r < 1 << 52 and r % 4096 == 0 for r in (a, b))
                    and 0xffff800000000000 <= address < 0xffffff8000000000
                    and address % (1 << 39) == 0):
                raise RuntimeError('M1 paging proof has invalid root/window addresses')
            records[index - 1]['paging'] = {'root_a': a, 'root_b': b, 'virtual': address,
                'map_unmap': True, 'remap': True, 'zeroed': True, 'permission_bits': True, 'restored': True}
        elif matches:
            raise RuntimeError('Deliberate panic unexpectedly reached the paging proof')
    return records


original_verify = bootstrap.verify_boot
if __name__ == '__main__':
    bootstrap.verify_boot = verify_paging
    sys.exit(bootstrap.main('M1-02a', 'paging',
        'Bootstrap scratch roots and supervisor mappings only; no user isolation, fault recovery, reclamation or complete M1-02 acceptance.',
        ['kernel/src/mapping.rs', 'kernel/src/paging.rs', 'tools/m1/paging.py']))
