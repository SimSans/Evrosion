#!/usr/bin/env python3
"""Closed Internal logical File/Object codec generator; no generic IDL language."""
import argparse
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'idl/ev.internal.file.v1.json'
TEMPLATE=ROOT/'tools/idl/file.rs.in'
OUTPUT=ROOT/'libs/userspace-contract/src/file.rs'
EXPECTED='405c1fe452e336f8aa2c09d5add9b549979d12819a221a8ea68d41f9a18f6d93'
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate schema field: '+key)
        result[key]=value
    return result
def render(source,template):
    value=json.loads(source,object_pairs_hook=unique)
    canonical=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    if hashlib.sha256(canonical).hexdigest()!=EXPECTED:raise ValueError('unsupported ev.internal.file@1 schema')
    return template.replace('@SHA@',hashlib.sha256(source).hexdigest())
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    result=render(SOURCE.read_bytes(),TEMPLATE.read_text())
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text()!=result:raise SystemExit('generated File/Object contract is stale')
    else:OUTPUT.parent.mkdir(parents=True,exist_ok=True);OUTPUT.write_text(result)
if __name__=='__main__':main()
