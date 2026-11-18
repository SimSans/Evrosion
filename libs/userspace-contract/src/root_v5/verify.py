#!/usr/bin/env python3
"""Read-only independent ABI hashes and optional original V2-V4 source audit."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument('--baseline', type=Path)
args = parser.parse_args()
here = Path(__file__).resolve().parent
result = {'abi': {}, 'legacy': None}
for filename, description, saved_hash in (
        ('mod.rs', 'ABI_DESCRIPTION', 'ABI'),
        ('child.rs', 'ABI_DESCRIPTION', 'ABI'),
        ('dynamic.rs', 'DESCRIPTION', 'DESCRIPTION_SHA256')):
    source = (here / filename).read_text()
    literal = re.search(r'pub const ' + description + r':.*?= (b"[^"\n]*");', source).group(1)
    digest = hashlib.sha256(ast.literal_eval(literal)).digest()
    values = re.search(r'pub const ' + saved_hash + r': \[u8; 32\] = \[([^\]]+)\];', source, re.S).group(1)
    stored = bytes(int(value.strip(), 16) for value in values.split(',') if value.strip())
    if digest != stored:
        raise SystemExit(f'ABI mismatch: {filename}')
    result['abi'][filename] = digest.hex()
if args.baseline:
    original = args.baseline.resolve() / 'libs/userspace-contract/src'
    current = here.parent
    paths = [original / 'root_v2.rs', original / 'root_v4.rs']
    paths += [p for name in ('root_v2', 'root_v4') for p in (original / name).rglob('*') if p.is_file()]
    changed = [str(path.relative_to(original)) for path in paths
               if path.read_bytes() != (current / path.relative_to(original)).read_bytes()]
    result['legacy'] = {'files_compared': len(paths), 'changed': changed}
    if changed:
        raise SystemExit(json.dumps(result, sort_keys=True))
print(json.dumps(result, sort_keys=True))
