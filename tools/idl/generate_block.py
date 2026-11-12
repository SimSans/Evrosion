#!/usr/bin/env python3
"""Generate/check the closed Internal block envelope; no generic IDL language."""
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'idl/ev.internal.block.v1.json'
TEMPLATE=ROOT/'tools/idl/block.rs.in'
OUTPUT=ROOT/'libs/userspace-contract/src/block.rs'
EXPECTED={'schema': 1, 'interface': 'ev.internal.block', 'version': 1, 'maturity': 'Internal', 'application_boundary': 'backend_only_E010_File_Object_unchanged', 'wire': {'bytes': 8, 'magic': 'BL', 'endianness': 'little', 'logical_sector': 'u32', 'request_opcodes': {'read': 1, 'write': 2, 'flush': 3}, 'response_opcodes': {'read': 129, 'written': 130, 'flushed': 131, 'error': 255}, 'flush_sector': 0}, 'buffer': {'bytes': 512, 'sectors_per_request': 1, 'transport': 'prebound_shared_window', 'capabilities_per_message': 0, 'ownership': 'external_transport_must_prevent_concurrent_reuse'}, 'transport': {'max_outstanding': 1, 'deadline': 'finite_absolute_monotonic', 'automatic_retry': False, 'read_semantics': 'READ_ONLY', 'write_semantics': 'NONE', 'flush_semantics': 'NONE', 'timeout': 'not_proof_of_nonexecution_or_buffer_release', 'first_fixture': 'single_client_thread_no_admitted_timeout_before_controller_stop'}}
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate schema field: '+key)
        result[key]=value
    return result
def render(source,template):
    value=json.loads(source,object_pairs_hook=unique)
    canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'))
    if canonical(value)!=canonical(EXPECTED):raise ValueError('unsupported ev.internal.block@1 schema')
    return template.replace('@SHA@',hashlib.sha256(source).hexdigest())
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    result=render(SOURCE.read_bytes(),TEMPLATE.read_text())
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text()!=result:raise SystemExit('generated block contract is stale')
    else:OUTPUT.parent.mkdir(parents=True,exist_ok=True);OUTPUT.write_text(result)
if __name__=='__main__':main()
